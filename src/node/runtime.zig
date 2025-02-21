const std = @import("std");
const crypto = std.crypto;
const net = std.net;
const mem = std.mem;
const posix = std.posix;
const os = std.os;
const system = std.posix.system;
const fmt = std.fmt;

const kademlia = @import("kademlia.zig");
const e2e = @import("e2e.zig");

const Allocator = std.mem.Allocator;
const X25519 = crypto.dh.X25519;
const Ed25519 = crypto.sign.Ed25519;

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

    fn write(self: ID, writer: Connection.Writer) !void {
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

    pub fn read(reader: anytype) !ID {
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
    keys: Ed25519.KeyPair,
    listener: posix.socket_t = undefined,
    listener_address: net.Address = undefined,

    // for creating client
    client_pool: std.heap.MemoryPool(Client),
    loop: KQueue,
    allocator: Allocator,

    clients: std.HashMapUnmanaged(net.Address, *Client, AddressContext, std.hash_map.default_max_load_percentage),
    routing_table: kademlia.RoutingTable,

    pub fn init(allocator: mem.Allocator, keys: Ed25519.KeyPair, address: net.Address) !Node {
        return .{
            .id = .{ .public_key = keys.public_key.bytes, .address = address },
            .keys = keys,

            .clients = .{},
            .routing_table = .{ .public_key = keys.public_key.bytes },
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
                                client.write() catch |err| {
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
                        const pk = try client.reader().readBytesNoEof(32);
                        const sk = try crypto.dh.X25519.scalarmult(client.keys.secret_key, pk);

                        const peer_sig = Ed25519.Signature.fromBytes(try client.reader().readBytesNoEof(Ed25519.Signature.encoded_length));
                        try peer_sig.verify(client.conn.read_buffer[0 .. client.conn.read_end - Ed25519.Signature.encoded_length], try Ed25519.PublicKey.fromBytes(peer_id.public_key));

                        log.debug("{} signature matches from {}", .{ packet.tag, peer_id });
                        client.assignPeerID(peer_id);

                        switch (self.routing_table.put(peer_id)) {
                            .full => log.info("incoming handshake from {} (peer ignored)", .{peer_id}),
                            .updated => log.info("incoming handshake from {} (peer updated)", .{peer_id}),
                            .inserted => log.info("incoming handshake from {} (peer registered)", .{peer_id}),
                        }

                        try (Packet{
                            .op = .response,
                            .tag = .hello,
                        }).write(client.writer());

                        try self.id.write(client.writer());
                        try client.writer().writeAll(&client.keys.public_key);

                        const sig = try self.keys.sign(client.conn.write_buffer[0..client.conn.write_end], null);
                        try client.writer().writeAll(&sig.toBytes());

                        try client.write();

                        client.conn.enableFlag(Connection.Flag.signed);
                        try client.conn.enableEncryptionWithRemoteKey(sk, pk);
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
                            .op = .response,
                            .tag = .find_nodes,
                        }).write(client.writer());

                        try client.writer().writeInt(u8, @intCast(count), .little);
                        for (0..count) |i| {
                            try peer_ids[i].write(client.writer());
                        }

                        try client.write();
                    },
                    else => return error.UnexpectedTag,
                }
            },
            .response => return error.UnexpectedOp,
            .command => {
                switch (packet.tag) {
                    .route => {
                        const route = try Router.readRoute(self.allocator, client.reader(), @intCast(client.conn.read_end)); // TODO: remove hacky read_end

                        if (std.mem.eql(u8, &self.id.public_key, &route.dst)) {
                            log.debug("ack route from {}", .{fmt.fmtSliceHexLower(&route.src)});
                            log.debug("having to decrypt body: {x}", .{route.body});

                            const result = try Router.decrypt(self.allocator, self, route.src, route.ph, route.eh, route.body);
                            log.debug("decrypted: {s} ({x})", .{ result, result });
                            return;
                        }

                        const peer_id = pid: {
                            if (self.routing_table.get(route.dst)) |peer_id| {
                                break :pid peer_id;
                            } else {
                                var peer_ids: [16]ID = undefined;
                                const n = self.routing_table.closestTo(&peer_ids, route.dst);
                                if (n == 0) {
                                    log.warn("could not route to {}", .{fmt.fmtSliceHexLower(&route.dst)});
                                    return;
                                }
                                break :pid peer_ids[0]; // TODO: pick random peer
                            }
                        };

                        log.debug("fwd route to {}", .{peer_id});

                        const c = try self.getOrCreateClient(peer_id.address);

                        try (Packet{
                            .op = .command,
                            .tag = .route,
                        }).write(c.writer());

                        try c.writer().writeAll(&route.src);
                        try c.writer().writeAll(&route.dst);

                        try c.writer().writeInt(u8, @intCast(route.hops.len + 1), .little);
                        for (route.hops) |hop| {
                            try hop.write(c.writer());
                        }

                        try self.id.write(c.writer());

                        // Just passing it along! Nothing to do here :)
                        try route.ph.write(c.writer());
                        try route.eh.write(c.writer());
                        try c.writer().writeAll(route.body);

                        try c.write();
                    },
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
            log.info("shutting down client {}...", .{client_ptr.*.conn.socket});
            self.closeClient(client_ptr.*);
        }
    }

    fn closeClient(self: *Node, client: *Client) void {
        if (client.conn.peer_id) |peer_id| {
            if (self.routing_table.delete(peer_id.public_key)) {
                log.debug("closing client {} (peer removed)", .{peer_id});
            } else {
                log.debug("closing client {}", .{peer_id});
            }
        } else {
            log.debug("closing client {}", .{client.conn.socket});
        }

        posix.close(client.conn.socket);
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

        log.info("Accepted client: {}", .{client.conn.socket});
    }

    fn createClient(self: *Node, socket: posix.socket_t, address: net.Address) !*Client {
        const client: *Client = try self.client_pool.create();
        errdefer self.client_pool.destroy(client);

        client.* = Client.init(self.allocator, socket, address, &self.loop, &self.keys) catch |err| {
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
            log.info("connecting to {}", .{address});
            try posix.connect(socket, &address.any, address.getOsSockLen());

            const client = try self.createClient(socket, address);
            errdefer client.deinit(self.allocator);

            try (Packet{
                .op = .request,
                .tag = .hello,
            }).write(client.writer());

            try self.id.write(client.writer()); // server id
            try client.writer().writeAll(&client.keys.public_key); // connection key

            const sig = try self.keys.sign(client.conn.write_buffer[0..client.conn.write_end], null);
            try client.writer().writeAll(&sig.toBytes());

            try client.write();

            // wait for hello
            const response = try Packet.read(client.reader());
            switch (response.op) {
                .response => {
                    switch (response.tag) {
                        .hello => {
                            const peer_id = try ID.read(client.reader());
                            client.assignPeerID(peer_id);
                            const pk = try client.reader().readBytesNoEof(32);
                            const sk = try crypto.dh.X25519.scalarmult(client.keys.secret_key, pk);

                            const sig_bytes = try client.reader().readBytesNoEof(Ed25519.Signature.encoded_length);
                            const peer_sig = Ed25519.Signature.fromBytes(sig_bytes);

                            try peer_sig.verify(client.conn.read_buffer[0 .. client.conn.read_end - sig_bytes.len], try Ed25519.PublicKey.fromBytes(peer_id.public_key));
                            log.debug("{} signature matches from {}", .{ response.tag, peer_id });

                            switch (self.routing_table.put(peer_id)) {
                                .full => log.info("handshaked with {} (peer ignored)", .{peer_id}),
                                .updated => log.info("handshaked with {} (peer updated)", .{peer_id}),
                                .inserted => log.info("handshaked with {} (peer registered)", .{peer_id}),
                            }
                            client.conn.enableFlag(Connection.Flag.signed);
                            try client.conn.enableEncryptionWithKeyPair(sk, client.keys);
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

    loop: *KQueue,
    address: net.Address,

    conn: Connection,

    keys: X25519.KeyPair,

    fn init(
        allocator: Allocator,
        socket: posix.socket_t,
        address: std.net.Address,
        loop: *KQueue,
        server_kp: *Ed25519.KeyPair,
    ) !Client {
        _ = allocator; // autofix

        const keys = try X25519.KeyPair.create(null); // generate new KP for each client (used for e2e)

        return .{
            .loop = loop,
            .address = address,
            .keys = keys,
            .conn = .{
                .socket = socket,
                .server_kp = server_kp,
            },
        };
    }

    pub fn writer(self: *Client) Connection.Writer {
        return self.conn.writer();
    }

    pub fn reader(self: *Client) Connection.Reader {
        return self.conn.reader();
    }

    pub fn write(self: *Client) !void {
        try self.conn.flush();
    }

    fn assignPeerID(self: *Client, peer_id: ID) void {
        self.conn.peer_id = peer_id;
    }

    fn deinit(self: *Client, allocator: Allocator) void {
        _ = allocator; // autofix
        _ = self; // autofix
    }
};

pub const Connection = struct {
    const Self = @This();
    const log = std.log.scoped(.connection);

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    pub const Error = error{
        PacketTooBig,
    };
    pub const Flag = struct {
        const none: u8 = 0x0;
        const signed: u8 = 0x1;
        const encrypted: u8 = 0x2;
    };

    pub const Writer = std.io.Writer(*Self, Error, write);
    pub const Reader = std.io.Reader(*Self, anyerror, read);

    write_buffer: [Packet.max_len]u8 = undefined,
    write_end: usize = 0,

    read_buffer: [Packet.max_len]u8 = undefined,
    read_start: usize = 0,
    read_end: usize = 0,

    flags: u8 = Flag.none,

    peer_id: ?ID = null,
    session: ?e2e.Session = null,
    socket: posix.socket_t,
    server_kp: *Ed25519.KeyPair,

    fn read(self: *Self, dest: []u8) !usize {
        var dest_index: usize = 0;

        while (dest_index < dest.len) {
            const written = @min(dest.len - dest_index, self.read_end - self.read_start);

            @memcpy(dest[dest_index..][0..written], self.read_buffer[self.read_start..][0..written]);
            if (written == 0) {
                // buffer empty, read a *whole* packet in buffer
                const stream = net.Stream{ .handle = self.socket };
                var in = stream.reader();
                const header = try Packet.Header.read(in);
                var encryption_header: ?Packet.EncryptionHeader = null;

                log.debug("read header: {}", .{header});
                if (header.flags & Flag.encrypted != 0x0) {
                    encryption_header = try Packet.EncryptionHeader.read(in);
                }

                // read body
                const n = try in.read(self.read_buffer[0..header.len]);

                if (n == 0) {
                    // reading from the unbuffered stream returned nothing
                    // so we have nothing left to read.
                    return dest_index;
                }

                log.debug("read {} bytes in buffer", .{n});

                if (header.flags & Flag.signed != 0) {
                    const peer_id = self.peer_id orelse return error.EmptyPeerID;
                    var bytes: [Ed25519.Signature.encoded_length]u8 = undefined;
                    if (try in.read(&bytes) != bytes.len) {
                        return error.SignatureInvalid;
                    }

                    const sig = Ed25519.Signature.fromBytes(bytes);
                    const pub_key = try Ed25519.PublicKey.fromBytes(peer_id.public_key);

                    sig.verify(self.read_buffer[0..header.len], pub_key) catch {
                        log.warn("verified signature from {} (invalid)", .{peer_id});
                        return error.SignatureInvalid;
                    };

                    log.debug("verified signature from {} (ok)", .{peer_id});
                }

                if (header.flags & Flag.encrypted != 0) {
                    var session = self.session orelse return error.MissingSession;
                    const h = encryption_header orelse return error.MissingEncryptionHeader;

                    const result = try session.decrypt(.{
                        .dh = h.dh,
                        .n = h.n,
                        .pn = h.pn,

                        .cipher_text = self.read_buffer[0..header.len],
                    });

                    @memcpy(self.read_buffer[0..result.len], result);
                    self.read_start = 0;
                    self.read_end = result.len;

                    log.debug("dencrypted packet!", .{});
                    log.debug("data: {x}", .{result});
                } else {
                    self.read_start = 0;
                    self.read_end = header.len;
                }
            }

            self.read_start += written;
            dest_index += written;
        }

        return dest.len;
    }

    fn write(self: *Self, bytes: []const u8) Error!usize {
        if (self.write_end + bytes.len > self.write_buffer.len) {
            return error.PacketTooBig;
        }

        const new_end = self.write_end + bytes.len;
        @memcpy(self.write_buffer[self.write_end..new_end], bytes);
        self.write_end = new_end;
        return bytes.len;
    }

    fn flush(self: *Self) !void {
        var data_to_write = self.write_buffer[0..self.write_end];
        var encryption_header: ?Packet.EncryptionHeader = null;

        if (self.flags & Flag.encrypted != 0x0) {
            var session = self.session orelse return error.MissingSession;
            const result = try session.encrypt(data_to_write);
            data_to_write = result.cipher_text[0..];
            encryption_header = .{
                .dh = result.dh,
                .n = result.n,
                .pn = result.pn,
            };
            log.debug("encrypted packet!", .{});
        }

        const header = Packet.Header{
            .len = @intCast(data_to_write.len),
            .flags = self.flags,
        };

        const stream = net.Stream{ .handle = self.socket };
        var out = std.io.bufferedWriter(stream.writer());

        try header.write(out.writer());
        if (encryption_header) |h| {
            try h.write(out.writer());
        }

        try out.writer().writeAll(data_to_write);

        if (self.flags & Flag.signed != 0) {
            const sig = try self.server_kp.sign(data_to_write, null); // TODO: add noise
            try out.writer().writeAll(&sig.toBytes());
        }

        log.debug("data written: {x}", .{out.buf[0..out.end]});
        try out.flush();

        self.write_end = 0;
    }

    fn enableFlag(self: *Self, flag: u8) void {
        if (self.flags & flag != 0x0) {
            return;
        }

        self.flags |= flag;
        log.debug("enabled flag {}", .{flag});
    }

    /// Enables encryption using a remote public key.
    fn enableEncryptionWithRemoteKey(conn: *Self, shared_key: [32]u8, remote_key: [32]u8) !void {
        var session_id = generateSessionId();

        conn.session = try e2e.initRemoteKey(allocator, &session_id, shared_key, remote_key);
        log.debug("init e2e session ({}) with shared key {} (ok)", .{ fmt.fmtSliceHexLower(&session_id), fmt.fmtSliceHexLower(&shared_key) });
        conn.flags |= Flag.encrypted;
    }

    /// Enables encryption using an X25519 key pair.
    fn enableEncryptionWithKeyPair(conn: *Self, shared_key: [32]u8, keys: X25519.KeyPair) !void {
        var session_id = generateSessionId();

        log.debug("init e2e session ({}) with shared key {} (ok)", .{ fmt.fmtSliceHexLower(&session_id), fmt.fmtSliceHexLower(&shared_key) });

        conn.session = e2e.init(allocator, &session_id, shared_key, keys);
        conn.flags |= Flag.encrypted;
    }

    pub fn reader(self: *Self) Reader {
        return .{ .context = self };
    }

    pub fn writer(self: *Self) Writer {
        return .{ .context = self };
    }

    /// Generates a random session ID.
    fn generateSessionId() [16]u8 {
        var session_id: [16]u8 = undefined;
        crypto.random.bytes(&session_id);
        return session_id;
    }
};

pub const Router = struct {
    const log = std.log.scoped(.router);
    const Buffer = std.ArrayList(u8);

    buff: Buffer,
    src: [32]u8,
    dst: [32]u8,
    hops: []ID,
    session: e2e.Session,

    pub fn createRoute(allocator: std.mem.Allocator, node: *Node, dst: [32]u8) !Router {
        const dst_pub = try X25519.publicKeyFromEd25519(try Ed25519.PublicKey.fromBytes(dst));
        const keys = try X25519.KeyPair.fromEd25519(node.keys);

        const sk = try X25519.scalarmult(keys.secret_key, dst_pub);
        log.debug("route sk: {}", .{fmt.fmtSliceHexLower(&sk)});

        return .{
            .src = node.id.public_key,
            .dst = dst,
            .session = try e2e.initRemoteKey(allocator, "test", sk, dst_pub),
            .buff = Buffer.init(allocator),
            .hops = &[0]ID{},
        };
    }

    pub fn readRoute(allocator: std.mem.Allocator, r: Connection.Reader, size: u32) !struct {
        hops: []ID,
        src: [32]u8,
        dst: [32]u8,
        ph: Packet.Header,
        eh: Packet.EncryptionHeader,
        body: []u8,
    } {
        _ = size; // autofix
        var in = std.io.countingReader(r);
        const src = try in.reader().readBytesNoEof(32);
        const dst = try in.reader().readBytesNoEof(32);
        const count = try in.reader().readInt(u8, .little);
        if (count > 16) {
            return error.TooManyHops;
        }

        var hops: [16]ID = undefined;
        for (0..count) |i| {
            hops[i] = try ID.read(in.reader());
        }

        log.debug("{} => {} (hops: {any})", .{ fmt.fmtSliceHexLower(&src), fmt.fmtSliceHexLower(&dst), hops[0..count] });
        // const body = try allocator.alloc(u8, size - in.bytes_read + Packet.Header.size + Packet.EncryptionHeader.size); // minus IV len + sig len (because it's encrypted.. yikes >.<)
        // log.debug("want to read {} bytes", .{body.len});
        // _ = try in.reader().readAll(body);
        // log.debug("body: {x}", .{body});

        const ph = try Packet.Header.read(in.reader());
        const eh = try Packet.EncryptionHeader.read(in.reader());
        log.debug("ph: {}, eh: {}", .{ ph, eh });
        const body = try allocator.alloc(u8, ph.len);
        _ = try in.reader().readAll(body);

        return .{
            .hops = hops[0..count],
            .src = src,
            .dst = dst,
            .ph = ph,
            .eh = eh,
            .body = body,
        };
    }

    pub fn decrypt(allocator: std.mem.Allocator, node: *Node, src: [32]u8, ph: Packet.Header, eh: Packet.EncryptionHeader, cipher_text: []u8) ![]u8 {
        _ = ph; // autofix
        const keys = try X25519.KeyPair.fromEd25519(node.keys);
        const src_pub = try X25519.publicKeyFromEd25519(try Ed25519.PublicKey.fromBytes(src));
        const sk = try X25519.scalarmult(keys.secret_key, src_pub);
        log.debug("route sk: {}", .{fmt.fmtSliceHexLower(&sk)});

        var session = e2e.init(allocator, "test-2", sk, keys);

        const plain_text = try session.decrypt(.{
            .dh = eh.dh,
            .n = eh.n,
            .pn = eh.pn,
            .cipher_text = cipher_text,
        });

        return plain_text;
    }

    pub fn writer(self: *Router) Buffer.Writer {
        return self.buff.writer();
    }

    pub fn write(self: *Router, w: Connection.Writer) !void {
        try (Packet{
            .op = .command,
            .tag = .route,
        }).write(w);

        try w.writeAll(&self.src);
        try w.writeAll(&self.dst);

        // amount of hops
        try w.writeInt(u8, 0, .little);

        // TODO: this is duplication of client writer
        const result = try self.session.encrypt(self.buff.items);

        try (Packet.Header{
            .len = @intCast(result.cipher_text.len),
            .flags = Connection.Flag.encrypted,
        }).write(w);

        try (Packet.EncryptionHeader{
            .dh = result.dh,
            .n = result.n,
            .pn = result.pn,
        }).write(w);

        try w.writeAll(result.cipher_text);
        // TODO: siggy!
    }
};
pub const Packet = struct {
    const log = std.log.scoped(.packet);
    const max_len = 1024;
    const size = @sizeOf(u8) + @sizeOf(u8);

    pub const Header = struct {
        const size = @sizeOf(u32) + @sizeOf(u8);

        len: u32,
        flags: u8,

        fn write(h: Header, writer: anytype) !void {
            try writer.writeInt(u32, h.len, .little);
            try writer.writeInt(u8, h.flags, .little);
        }

        fn read(reader: anytype) !Header {
            const len = try reader.readInt(u32, .little);
            const flags = try reader.readInt(u8, .little);

            return .{
                .len = len,
                .flags = flags,
            };
        }
    };

    pub const EncryptionHeader = struct {
        const size = @sizeOf([32]u8) + @sizeOf(u32) + @sizeOf(u32);

        dh: [32]u8,
        n: u32,
        pn: u32,

        fn write(h: EncryptionHeader, writer: anytype) !void {
            try writer.writeAll(&h.dh);
            try writer.writeInt(u32, h.n, .little);
            try writer.writeInt(u32, h.pn, .little);
        }

        fn read(reader: anytype) !EncryptionHeader {
            const dh = try reader.readBytesNoEof(32);
            const n = try reader.readInt(u32, .little);
            const pn = try reader.readInt(u32, .little);

            return .{
                .dh = dh,
                .n = n,
                .pn = pn,
            };
        }
    };

    const Op = enum(u8) {
        request,
        response,
        command,
    };

    const Tag = enum(u8) {
        ping,
        hello,
        find_nodes,
        route,
        echo,
    };

    op: Op,
    tag: Tag,

    pub fn write(p: Packet, writer: anytype) !void {
        try writer.writeInt(u8, @intFromEnum(p.op), .little);
        try writer.writeInt(u8, @intFromEnum(p.tag), .little);
        log.debug("wrote packet: {}", .{p});
    }

    pub fn read(reader: anytype) !Packet {
        const op: Packet.Op = @enumFromInt(try reader.readInt(u8, .little));
        const tag: Packet.Tag = @enumFromInt(try reader.readInt(u8, .little));

        const packet = Packet{
            .op = op,
            .tag = tag,
        };
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
            .ident = @intCast(client.conn.socket),
            .filter = posix.system.EVFILT_READ,
            .flags = posix.system.EV_ADD,
            .fflags = 0,
            .data = 0,
            .udata = @intFromPtr(client),
        });

        try self.queueChange(.{
            .ident = @intCast(client.conn.socket),
            .filter = posix.system.EVFILT_WRITE,
            .flags = posix.system.EV_ADD | posix.system.EV_DISABLE,
            .fflags = 0,
            .data = 0,
            .udata = @intFromPtr(client),
        });
    }

    fn readMode(self: *KQueue, client: *Client) !void {
        try self.queueChange(.{
            .ident = @intCast(client.conn.socket),
            .filter = posix.system.EVFILT_WRITE,
            .flags = posix.system.EV_DISABLE,
            .fflags = 0,
            .data = 0,
            .udata = 0,
        });

        try self.queueChange(.{
            .ident = @intCast(client.conn.socket),
            .filter = posix.system.EVFILT_READ,
            .flags = posix.system.EV_ENABLE,
            .fflags = 0,
            .data = 0,
            .udata = @intFromPtr(client),
        });
    }

    fn writeMode(self: *KQueue, client: *Client) !void {
        try self.queueChange(.{
            .ident = @intCast(client.conn.socket),
            .filter = posix.system.EVFILT_READ,
            .flags = posix.system.EV_DISABLE,
            .fflags = 0,
            .data = 0,
            .udata = 0,
        });

        try self.queueChange(.{
            .ident = @intCast(client.conn.socket),
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
