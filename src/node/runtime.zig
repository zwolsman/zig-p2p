const std = @import("std");
const crypto = std.crypto;
const net = std.net;
const mem = std.mem;
const posix = std.posix;
const os = std.os;
const system = std.posix.system;
const fmt = std.fmt;

const kademlia = @import("kademlia.zig");

const Allocator = std.mem.Allocator;
const X25519 = crypto.dh.X25519;

pub const ID = struct {
    public_key: [32]u8,
    address: net.Address,

    // pub key + type + ip + port
    fn size(self: ID) u32 {
        return @sizeOf([32]u8) + @sizeOf(u8) + @as(u32, switch (self.address.any.family) {
            posix.AF.INET => @sizeOf([4]u8),
            posix.AF.INET6 => @sizeOf([16]u8) + @sizeOf(u32),
            else => unreachable,
        }) + @sizeOf(u16);
    }

    pub fn format(self: ID, comptime layout: []const u8, options: fmt.FormatOptions, writer: anytype) !void {
        _ = layout;
        _ = options;
        try fmt.format(writer, "{}[{}]", .{ self.address, fmt.fmtSliceHexLower(&self.public_key) });
    }

    fn write(self: ID, writer: Client.Writer) !void {
        try writer.writeAll(&self.public_key);
        try writer.writeByte(@intCast(self.address.any.family));
        switch (self.address.any.family) {
            posix.AF.INET => {
                try writer.writeInt(u32, self.address.in.sa.addr, .little);
                try writer.writeInt(u16, self.address.in.sa.port, .little);
            },
            posix.AF.INET6 => return error.UnsupportedAddress, // TODO
            else => unreachable,
        }
    }

    pub fn read(reader: Client.Reader) !ID {
        var id: ID = undefined;
        id.public_key = try reader.readBytesNoEof(32);

        switch (try reader.readByte()) {
            posix.AF.INET => {
                const addr = net.Ip4Address{ .sa = .{ .addr = try reader.readInt(u32, .little), .port = try reader.readInt(u16, .little) } };

                id.address = .{ .in = addr };
            },
            posix.AF.INET6 => return error.UnsupportedAddress, // TODO
            else => unreachable,
        }

        return id;
    }
};

pub const Node = struct {
    const log = std.log.scoped(.node);

    id: ID,
    keys: X25519.KeyPair,
    listener: posix.socket_t = undefined,
    listener_address: net.Address = undefined,

    // for creating client
    client_pool: std.heap.MemoryPool(Client),
    loop: KQueue,
    allocator: Allocator,

    clients: std.HashMapUnmanaged(net.Address, *Client, AddressContext, std.hash_map.default_max_load_percentage),
    routing_table: kademlia.RoutingTable,

    pub fn init(allocator: mem.Allocator, keys: X25519.KeyPair, address: net.Address) !Node {
        return .{
            .keys = keys,
            .id = .{ .public_key = keys.public_key, .address = address },

            .clients = .{},
            .routing_table = .{ .public_key = keys.public_key },
            .allocator = allocator,

            .client_pool = std.heap.MemoryPool(Client).init(allocator),
            .loop = try KQueue.init(),
        };
    }

    pub fn listen(self: *Node, address: net.Address) !void {
        const tpe: u32 = posix.SOCK.STREAM | posix.SOCK.NONBLOCK;
        const protocol = posix.IPPROTO.TCP;
        const listener = try posix.socket(address.any.family, tpe, protocol);

        try posix.setsockopt(listener, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
        try posix.bind(listener, &address.any, address.getOsSockLen());
        try posix.listen(listener, 128);

        var bound_address: net.Address = address;
        var addr_len = bound_address.getOsSockLen();
        try posix.getsockname(listener, &bound_address.any, &addr_len);

        self.listener = listener;
        self.listener_address = bound_address;
        self.id.address = bound_address;
        try self.loop.addListener(self.listener);

        log.debug("Bound to address {}", .{bound_address});
    }

    pub fn run(self: *Node) !void {
        while (true) {
            // const next_timeout = self.enforceTimeout();
            const ready_events = try self.loop.wait(1000);

            for (ready_events) |ready| {
                switch (ready.udata) {
                    0 => self.accept(self.listener) catch |err| log.err("failed to accept: {}", .{err}),
                    else => |nptr| {
                        const filter = ready.filter;
                        const client: *Client = @ptrFromInt(nptr);

                        switch (filter) {
                            system.EVFILT_READ => {
                                // can read the socket
                                const packet = Packet.read(client.reader()) catch |err| {
                                    log.err("failed to read: {}", .{err});
                                    self.closeClient(client);
                                    break;
                                };

                                self.handleServerPacket(client, packet) catch |err| {
                                    log.warn("could not handle packet: {}", .{err});
                                };
                            },
                            system.EVFILT_WRITE => {
                                // can write to the socket
                                //TODO:
                                client.writer_stream.flush() catch |err| {
                                    log.err("failed to write: {}", .{err});
                                    self.closeClient(client);
                                    break;
                                };
                            },
                            else => unreachable,
                        }
                    },
                }
            }
        }
    }

    fn handleServerPacket(self: *Node, client: *Client, packet: Packet) !void {
        switch (packet.op) {
            .request => {
                switch (packet.tag) {
                    .hello => {
                        const peer_id = try ID.read(client.reader());
                        client.peer_id = peer_id;

                        switch (self.routing_table.put(peer_id)) {
                            .full => log.info("incoming handshake from {} (peer ignored)", .{peer_id}),
                            .updated => log.info("incoming handshake from {} (peer updated)", .{peer_id}),
                            .inserted => log.info("incoming handshake from {} (peer registered)", .{peer_id}),
                        }

                        const p = Packet{
                            .len = self.id.size(),
                            .flags = 0x0,
                            .op = .response,
                            .tag = .hello,
                        };

                        try p.write(client.writer());
                        try self.id.write(client.writer());

                        try client.writer_stream.flush();
                    },
                    .find_nodes => {
                        const public_key = try client.reader().readBytesNoEof(32);
                        var peer_ids: [16]ID = undefined;
                        const count = self.routing_table.closestTo(&peer_ids, public_key);
                        log.debug("found {} clients for {}", .{ count, fmt.fmtSliceHexLower(&public_key) });

                        var len: u32 = @sizeOf(u8);
                        for (0..count) |i| {
                            len += peer_ids[i].size();
                        }

                        try (Packet{
                            .len = len,
                            .flags = 0,
                            .op = .response,
                            .tag = .find_nodes,
                        }).write(client.writer());

                        try client.writer().writeInt(u8, @intCast(count), .little);
                        for (0..count) |i| {
                            try peer_ids[i].write(client.writer());
                        }

                        try client.writer_stream.flush();
                    },
                    else => return error.UnexpectedTag,
                }
            },
            .response => {
                switch (packet.tag) {
                    else => return error.UnexpectedTag,
                }
            },
        }
    }

    pub fn deinit(self: *Node) void {
        log.info("Shutting down..", .{});
        posix.close(self.listener);
        var client_it = self.clients.valueIterator();
        while (client_it.next()) |client_ptr| {
            log.info("shutting down client {}...", .{client_ptr.*.socket});
            self.closeClient(client_ptr.*);
        }
    }

    fn closeClient(self: *Node, client: *Client) void {
        if (client.peer_id) |peer_id| {
            if (self.routing_table.delete(peer_id.public_key)) {
                log.debug("closing client {} (peer removed)", .{peer_id});
            } else {
                log.debug("closing client {}", .{peer_id});
            }
        } else {
            log.debug("closing client {}", .{client.socket});
        }

        posix.close(client.socket);
        client.deinit(self.allocator);
        self.client_pool.destroy(client);
    }

    fn accept(self: *Node, listener: posix.socket_t) !void {
        var address: net.Address = undefined;
        var address_len: posix.socklen_t = @sizeOf(net.Address);
        const socket = posix.accept(listener, &address.any, &address_len, posix.SOCK.NONBLOCK) catch |err| switch (err) {
            error.WouldBlock => return,
            else => return err,
        };

        const client = try self.createClient(socket, address);
        try self.loop.newClient(client);

        log.info("Accepted client: {}", .{client.socket});
    }

    fn createClient(self: *Node, socket: posix.socket_t, address: net.Address) !*Client {
        const client: *Client = try self.client_pool.create();
        errdefer self.client_pool.destroy(client);

        client.* = Client.init(self.allocator, socket, address, &self.loop) catch |err| {
            posix.close(socket);
            log.err("failed to initialize client: {}", .{err});
            return err;
        };

        errdefer client.deinit(self.allocator);

        return client;
    }

    pub fn getOrCreateClient(self: *Node, address: net.Address) !*Client {
        const result = try self.clients.getOrPut(self.allocator, address);
        if (!result.found_existing) {
            errdefer std.debug.assert(self.clients.remove(address));

            const tpe: u32 = posix.SOCK.STREAM;
            const protocol = posix.IPPROTO.TCP;
            const socket = try posix.socket(address.any.family, tpe, protocol);
            log.debug("connecting to {}", .{address});
            try posix.connect(socket, &address.any, address.getOsSockLen());

            const client = try self.createClient(socket, address);
            errdefer client.deinit(self.allocator);

            const p = Packet{
                .len = 32,
                .flags = 0,
                .op = .request,
                .tag = .hello,
            };

            try p.write(client.writer());
            try self.id.write(client.writer());

            try client.writer_stream.flush();

            // wait for hello
            const response = try Packet.read(client.reader());
            switch (response.op) {
                .response => {
                    switch (response.tag) {
                        .hello => {
                            const peer_id = try ID.read(client.reader());

                            client.peer_id = peer_id;
                            switch (self.routing_table.put(peer_id)) {
                                .full => log.info("handshaked with {} (peer ignored)", .{peer_id}),
                                .updated => log.info("handshaked with {} (peer updated)", .{peer_id}),
                                .inserted => log.info("handshaked with {} (peer registered)", .{peer_id}),
                            }
                        },
                        else => return error.UnexpectedTag,
                    }
                },
                else => return error.UnexpectedOp,
            }

            try posix.setsockopt(socket, posix.SOL.SOCKET, posix.SOCK.NONBLOCK, &std.mem.toBytes(@as(c_int, 1)));
            try self.loop.newClient(client);
            result.value_ptr.* = client;
        }

        return result.value_ptr.*;
    }
};

const Client = struct {
    const log = std.log.scoped(.client);
    const BufferedWriter = std.io.BufferedWriter(Packet.max_size, net.Stream.Writer);
    const BufferedReader = std.io.BufferedReader(4096, net.Stream.Reader);
    const Writer = BufferedWriter.Writer;
    const Reader = BufferedReader.Reader;

    loop: *KQueue,
    address: net.Address,
    socket: posix.socket_t,

    writer_stream: BufferedWriter,
    reader_stream: BufferedReader,

    peer_id: ?ID = null,

    fn init(
        allocator: Allocator,
        socket: posix.socket_t,
        address: std.net.Address,
        loop: *KQueue,
    ) !Client {
        _ = allocator; // autofix

        const stream = net.Stream{ .handle = socket };

        return .{
            .loop = loop,
            .address = address,
            .socket = socket,

            .writer_stream = BufferedWriter{ .unbuffered_writer = stream.writer() },
            .reader_stream = BufferedReader{ .unbuffered_reader = stream.reader() },
        };
    }

    fn writer(self: *Client) Writer {
        return .{ .context = &self.writer_stream };
    }

    pub fn reader(self: *Client) Reader {
        return .{ .context = &self.reader_stream };
    }

    fn deinit(self: *Client, allocator: Allocator) void {
        _ = allocator; // autofix
        _ = self; // autofix
    }
};

pub const Packet = struct {
    const log = std.log.scoped(.packet);
    const max_size = 1024;

    const Op = enum(u8) {
        request,
        response,
    };

    const Tag = enum(u8) {
        ping,
        hello,
        find_nodes,
    };

    len: u32,
    flags: u8,
    op: Op,
    tag: Tag,

    pub fn write(p: Packet, writer: Client.Writer) !void {
        if (p.len > Packet.max_size) {
            return error.PacketTooBig;
        }

        try writer.writeInt(u32, p.len, .little);
        try writer.writeInt(u8, p.flags, .little);
        try writer.writeInt(u8, @intFromEnum(p.op), .little);
        try writer.writeInt(u8, @intFromEnum(p.tag), .little);
        log.debug("wrote packet: {}", .{p});
    }

    pub fn read(reader: Client.Reader) !Packet {
        const len = try reader.readInt(u32, .little);
        if (len > Packet.max_size) {
            return error.PacketTooBig;
        }

        const flags = try reader.readInt(u8, .little);
        const op: Packet.Op = @enumFromInt(try reader.readInt(u8, .little));
        const tag: Packet.Tag = @enumFromInt(try reader.readInt(u8, .little));

        const packet = Packet{
            .len = len,
            .flags = flags,
            .op = op,
            .tag = tag,
        };
        log.debug("read packet: {}", .{packet});
        return packet;
    }
};

pub const AddressContext = struct {
    const log = std.log.scoped(.address_context);
    pub fn hash(_: @This(), address: net.Address) u64 {
        return hashIpAddress(address);
    }

    pub fn eql(_: @This(), a: net.Address, b: net.Address) bool {
        if (a.any.family != b.any.family)
            return false;

        return a.eql(b);
    }
};

fn hashIpAddress(address: net.Address) u64 {
    var hasher = std.hash.Wyhash.init(0);
    switch (address.any.family) {
        posix.AF.INET => {
            hasher.update(mem.asBytes(&address.in.sa.addr));
            hasher.update(mem.asBytes(&address.in.sa.port));
        },
        posix.AF.INET6 => {
            hasher.update(mem.asBytes(&address.in6.sa.addr));
            hasher.update(mem.asBytes(&address.in6.sa.scope_id));
            hasher.update(mem.asBytes(&address.in6.sa.port));
        },
        else => unreachable,
    }
    return hasher.final();
}

// We'll eventually need to build a platform abstractions between epoll and
// kqueue. This is a rough start.
const KQueue = struct {
    kfd: posix.fd_t,
    event_list: [128]system.Kevent = undefined,
    change_list: [16]system.Kevent = undefined,
    change_count: usize = 0,

    fn init() !KQueue {
        const kfd = try posix.kqueue();
        return .{ .kfd = kfd };
    }

    fn deinit(self: KQueue) void {
        posix.close(self.kfd);
    }

    fn wait(self: *KQueue, timeout_ms: i32) ![]system.Kevent {
        const timeout = posix.timespec{
            .tv_sec = @intCast(@divTrunc(timeout_ms, 1000)),
            .tv_nsec = @intCast(@mod(timeout_ms, 1000) * 1000000),
        };
        const count = try posix.kevent(self.kfd, self.change_list[0..self.change_count], &self.event_list, &timeout);
        self.change_count = 0;
        return self.event_list[0..count];
    }

    fn addListener(self: *KQueue, listener: posix.socket_t) !void {
        // ok to use EV_ADD to renable the listener if it was previous
        // disabled via removeListener
        try self.queueChange(.{
            .ident = @intCast(listener),
            .filter = posix.system.EVFILT_READ,
            .flags = posix.system.EV_ADD,
            .fflags = 0,
            .data = 0,
            .udata = 0,
        });
    }

    fn removeListener(self: *KQueue, listener: posix.socket_t) !void {
        try self.queueChange(.{
            .ident = @intCast(listener),
            .filter = posix.system.EVFILT_READ,
            .flags = posix.system.EV_DISABLE,
            .fflags = 0,
            .data = 0,
            .udata = 0,
        });
    }

    fn newClient(self: *KQueue, client: *Client) !void {
        try self.queueChange(.{
            .ident = @intCast(client.socket),
            .filter = posix.system.EVFILT_READ,
            .flags = posix.system.EV_ADD,
            .fflags = 0,
            .data = 0,
            .udata = @intFromPtr(client),
        });

        try self.queueChange(.{
            .ident = @intCast(client.socket),
            .filter = posix.system.EVFILT_WRITE,
            .flags = posix.system.EV_ADD | posix.system.EV_DISABLE,
            .fflags = 0,
            .data = 0,
            .udata = @intFromPtr(client),
        });
    }

    fn readMode(self: *KQueue, client: *Client) !void {
        try self.queueChange(.{
            .ident = @intCast(client.socket),
            .filter = posix.system.EVFILT_WRITE,
            .flags = posix.system.EV_DISABLE,
            .fflags = 0,
            .data = 0,
            .udata = 0,
        });

        try self.queueChange(.{
            .ident = @intCast(client.socket),
            .filter = posix.system.EVFILT_READ,
            .flags = posix.system.EV_ENABLE,
            .fflags = 0,
            .data = 0,
            .udata = @intFromPtr(client),
        });
    }

    fn writeMode(self: *KQueue, client: *Client) !void {
        try self.queueChange(.{
            .ident = @intCast(client.socket),
            .filter = posix.system.EVFILT_READ,
            .flags = posix.system.EV_DISABLE,
            .fflags = 0,
            .data = 0,
            .udata = 0,
        });

        try self.queueChange(.{
            .ident = @intCast(client.socket),
            .filter = posix.system.EVFILT_WRITE,
            .flags = posix.system.EV_ENABLE,
            .fflags = 0,
            .data = 0,
            .udata = @intFromPtr(client),
        });
    }

    fn queueChange(self: *KQueue, event: system.Kevent) !void {
        var count = self.change_count;
        if (count == self.change_list.len) {
            // our change_list batch is full, apply it
            _ = try posix.kevent(self.kfd, &self.change_list, &.{}, null);
            count = 0;
        }
        self.change_list[count] = event;
        self.change_count = count + 1;
    }
};
