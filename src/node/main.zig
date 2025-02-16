const std = @import("std");
const net = std.net;
const posix = std.posix;
const system = std.posix.system;
const Allocator = std.mem.Allocator;
const proto = @import("protocol.zig");
const Crypto = @import("crypto.zig");
const enc = @import("doubleratchet.zig");

const flags = @import("flags");
const CliFlags = @import("cliflags.zig");

const log = std.log;
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const alloc = gpa.allocator();

pub fn main() !void {
    // for Windows compatibility: feed an allocator for args parsing
    var args = try std.process.argsWithAllocator(alloc);
    defer args.deinit();

    const cliflags = flags.parseOrExit(&args, "node", CliFlags, .{});

    const listen_addr = try net.Address.parseIp(cliflags.addr, cliflags.port);

    var server = Server.init(alloc, 4096) catch {
        log.err("Could not initialise server", .{});
        return;
    };

    const s = try server.start(listen_addr);
    s.detach();

    //TODO: server.join();

    var client = try BlockingClient.init(alloc, listen_addr);

    log.debug("Created blocking client\npriv: {x:0>2}\npub: {x:0>2}\n\n", .{ client.kp.secret_key, client.kp.public_key });

    try client.connect(listen_addr);
    log.info("Connected to server: {}", .{listen_addr});

    try client.run();
}

const BlockingClient = struct {
    const Self = @This();
    const l = std.log.scoped(.blocking_client);

    reader: Reader,
    kp: Crypto.KeyPair,
    sk: Crypto.Key,
    socket: posix.socket_t,
    encryption: bool,
    session: enc.Session = undefined,

    fn init(allocator: Allocator, address: net.Address) !Self {
        const protocol = posix.IPPROTO.TCP;
        const socket = try posix.socket(address.in.sa.family, posix.SOCK.STREAM, protocol);
        try posix.setsockopt(socket, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
        return Self{
            .socket = socket,
            .reader = try Reader.init(allocator, 1024),
            .kp = try Crypto.generateKeypair(),
            .sk = [_]u8{0} ** 32,
            .encryption = false,
        };
    }

    fn connect(self: *Self, address: net.Address) error{CouldntConnect}!void {
        for (0..5) |_| {
            posix.connect(self.socket, &address.any, address.getOsSockLen()) catch {
                std.time.sleep(1_000_000_000); // 1s
                continue;
            };

            return;
        }

        return error.CouldntConnect;
    }

    fn run(self: *Self) !void {
        defer posix.close(self.socket);
        try self.handshake();
        const in = std.io.getStdIn().reader();

        while (true) {
            var read_buf: [4096]u8 = undefined;
            const msg = try in.readUntilDelimiter(&read_buf, '\n');

            try self.writeMessage(proto.Message{ .Echo = msg });
        }
    }

    fn handshake(self: *Self) !void {
        l.debug("Starting handshake..", .{});
        const msg = self.reader.readMessage(self.socket) catch |err| {
            l.err("Could not obtain server key: {}", .{err});
            return err;
        };

        switch (msg) {
            .serverKey => |key| {
                self.sk = try Crypto.DH(self.kp, key);
                l.debug("Initialised shared key: {x:0>2}", .{self.sk});
                self.session = try enc.initRemoteKey(alloc, "blocking-client", self.sk, key);
            },
            else => return error.UnexpectedPacket,
        }

        try self.writeMessage(proto.Message{ .clientKey = self.kp.public_key });
        self.encryption = true;

        l.debug("Did handshake. Welcome user!", .{});
    }

    fn writeMessage(self: *Self, m: proto.Message) !void {
        const data = try m.encode(alloc);

        if (self.encryption) {
            const r = try self.session.RatchetEncrypt(data);
            const header = proto.EncMessageHeader.forMessage(r.ciphertext, r.header.DH, r.header.N, r.header.PN).encode();

            const buff = try alloc.alloc(u8, r.ciphertext.len + header.len);
            @memcpy(buff[0..header.len], &header);
            @memcpy(buff[header.len..], r.ciphertext);

            _ = try posix.write(self.socket, buff);
        } else {
            const header = proto.MessageHeader.forMessage(data).encode();

            const buff = try alloc.alloc(u8, data.len + header.len);
            @memcpy(buff[0..header.len], &header);
            @memcpy(buff[header.len..], data);

            _ = try posix.write(self.socket, buff);
        }
    }
};

fn runServer(server: *Server, addr: net.Address) void {
    defer server.deinit();

    std.debug.print("Listening on {}\n", .{addr});
    server.run(addr) catch |err| {
        log.err("Failed to run server: {}", .{err});
    };

    std.debug.print("Stopped\n", .{});
}

// 1 minute
const READ_TIMEOUT_MS = 60_000;

const ClientList = std.DoublyLinkedList(*Client);
const ClientNode = ClientList.Node;

const Server = struct {
    // maximum # of allowed clients
    max: usize,

    loop: KQueue,

    // creates our polls and clients slices and is passed to Client.init
    // for it to create our read buffer.
    allocator: Allocator,

    // The number of clients we currently have connected
    connected: usize,

    read_timeout_list: ClientList,

    // for creating client
    client_pool: std.heap.MemoryPool(Client),
    // for creating nodes for our read_timeout list
    client_node_pool: std.heap.MemoryPool(ClientList.Node),

    fn init(allocator: Allocator, max: usize) !Server {
        const loop = try KQueue.init();
        errdefer loop.deinit();

        const clients = try allocator.alloc(*Client, max);
        errdefer allocator.free(clients);

        return .{
            .max = max,
            .loop = loop,
            .connected = 0,
            .allocator = allocator,
            .read_timeout_list = .{},
            .client_pool = std.heap.MemoryPool(Client).init(allocator),
            .client_node_pool = std.heap.MemoryPool(ClientNode).init(allocator),
        };
    }

    fn deinit(self: *Server) void {
        self.loop.deinit();
        self.client_pool.deinit();
        self.client_node_pool.deinit();
    }

    fn start(self: *Server, address: std.net.Address) !std.Thread {
        return std.Thread.spawn(.{}, run, .{ self, address });
    }

    fn run(self: *Server, address: std.net.Address) !void {
        const tpe: u32 = posix.SOCK.STREAM | posix.SOCK.NONBLOCK;
        const protocol = posix.IPPROTO.TCP;
        const listener = try posix.socket(address.any.family, tpe, protocol);
        defer posix.close(listener);

        try posix.setsockopt(listener, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
        try posix.bind(listener, &address.any, address.getOsSockLen());
        try posix.listen(listener, 128);
        var read_timeout_list = &self.read_timeout_list;

        try self.loop.addListener(listener);

        while (true) {
            const next_timeout = self.enforceTimeout();
            const ready_events = try self.loop.wait(next_timeout);
            for (ready_events) |ready| {
                switch (ready.udata) {
                    0 => self.accept(listener) catch |err| log.err("failed to accept: {}", .{err}),
                    else => |nptr| {
                        const filter = ready.filter;
                        const client: *Client = @ptrFromInt(nptr);

                        if (filter == system.EVFILT_READ) {
                            // this socket is ready to be read
                            while (true) {
                                const msg = client.readMessage() catch |err| {
                                    log.err("failed to read: {}", .{err});
                                    self.closeClient(client);
                                    break;
                                } orelse break; // no more messages

                                client.handleMessage(msg) catch |err| {
                                    log.warn("failed to process msg: {}", .{err});
                                    continue;
                                };

                                client.read_timeout = std.time.milliTimestamp() + READ_TIMEOUT_MS;
                                read_timeout_list.remove(client.read_timeout_node);
                                read_timeout_list.append(client.read_timeout_node);
                            }
                        } else if (filter == system.EVFILT_WRITE) {
                            client.write() catch self.closeClient(client);
                        }
                    },
                }
            }
        }
    }

    fn enforceTimeout(self: *Server) i32 {
        const now = std.time.milliTimestamp();
        var node = self.read_timeout_list.first;
        while (node) |n| {
            const client = n.data;
            const diff = client.read_timeout - now;
            if (diff > 0) {
                // this client's timeout is the first one that's in the
                // future, so we now know the maximum time we can block on
                // poll before having to call enforceTimeout again
                return @intCast(diff);
            }

            // This client's timeout is in the past. Close the socket
            // Ideally, we'd call server.removeClient() and just remove the
            // client directly. But within this method, we don't know the
            // client_polls index. When we move to epoll / kqueue, this problem
            // will go away, since we won't need to maintain polls and client_polls
            // in sync by index.
            posix.shutdown(client.socket, .recv) catch {};
            node = n.next;
        } else {
            // We have no client that times out in the future (if we did
            // we would have hit the return above).
            return -1;
        }
    }

    fn accept(self: *Server, listener: posix.socket_t) !void {
        const space = self.max - self.connected;
        for (0..space) |_| {
            var address: net.Address = undefined;
            var address_len: posix.socklen_t = @sizeOf(net.Address);
            const socket = posix.accept(listener, &address.any, &address_len, posix.SOCK.NONBLOCK) catch |err| switch (err) {
                error.WouldBlock => return,
                else => return err,
            };

            const client: *Client = try self.client_pool.create();
            errdefer self.client_pool.destroy(client);
            client.* = Client.init(self.allocator, socket, address, &self.loop) catch |err| {
                posix.close(socket);
                log.err("failed to initialize client: {}", .{err});
                return;
            };
            errdefer client.deinit(self.allocator);

            client.read_timeout = std.time.milliTimestamp() + READ_TIMEOUT_MS;
            client.read_timeout_node = try self.client_node_pool.create();
            errdefer self.client_node_pool.destroy(client.read_timeout_node);

            client.read_timeout_node.* = .{
                .next = null,
                .prev = null,
                .data = client,
            };
            self.read_timeout_list.append(client.read_timeout_node);
            try self.loop.newClient(client);

            try client.writeProtoMessage(proto.Message{ .serverKey = client.kp.public_key });
            self.connected += 1;
        } else {
            // we've run out of space, stop monitoring the listening socket
            try self.loop.removeListener(listener);
        }
    }

    fn closeClient(self: *Server, client: *Client) void {
        self.read_timeout_list.remove(client.read_timeout_node);

        posix.close(client.socket);
        self.client_node_pool.destroy(client.read_timeout_node);
        client.deinit(self.allocator);
        self.client_pool.destroy(client);
    }
};

const Client = struct {
    loop: *KQueue,

    socket: posix.socket_t,
    address: std.net.Address,

    // Used to read length-prefixed messages
    reader: Reader,

    // Bytes we still need to send. This is a slice of `write_buf`. When
    // empty, then we're in "read-mode" and are waiting for a message from the
    // client.
    to_write: []u8,

    // Buffer for storing our length-prefixed messaged
    write_buf: []u8,

    // absolute time, in millisecond, when this client should timeout if
    // a message isn't received
    read_timeout: i64,

    // Node containing this client in the server's read_timeout_list
    read_timeout_node: *ClientNode,

    kp: Crypto.KeyPair,

    fn init(allocator: Allocator, socket: posix.socket_t, address: std.net.Address, loop: *KQueue) !Client {
        const reader = try Reader.init(allocator, 4096);
        errdefer reader.deinit(allocator);

        const write_buf = try allocator.alloc(u8, 4096);
        errdefer allocator.free(write_buf);

        return .{
            .loop = loop,
            .reader = reader,
            .socket = socket,
            .address = address,
            .to_write = &.{},
            .write_buf = write_buf,
            .read_timeout = 0, // let the server set this
            .read_timeout_node = undefined, // hack/ugly, let the server set this when init returns
            .kp = try Crypto.generateKeypair(),
        };
    }

    fn deinit(self: *const Client, allocator: Allocator) void {
        self.reader.deinit(allocator);
        allocator.free(self.write_buf);
    }

    fn readMessage(self: *Client) !?proto.Message {
        return self.reader.readMessage(self.socket) catch |err| switch (err) {
            error.WouldBlock => return null,
            else => return err,
        };
    }

    fn writeProtoMessage(self: *Client, msg: proto.Message) !void {
        return self.writeMessage(try msg.encode(alloc));
    }

    fn writeMessage(self: *Client, msg: []const u8) !void {
        if (self.to_write.len > 0) {
            // Depending on how you structure your code, this might not be possible
            // For example, in an HTTP server, the application might not control
            // the actual "writeMessage" call, and thus it would not be possible
            // to make more than one writeMessage call per request.
            // For this demo, we'll just return an error.
            return error.PendingMessage;
        }

        const header = proto.MessageHeader.forMessage(msg);

        const end = msg.len + proto.MessageHeader.size;
        if (end > self.write_buf.len) {
            // Could allocate a dynamic buffer. Could use a large buffer pool.
            return error.MessageTooLarge;
        }

        @memcpy(self.write_buf[0..proto.MessageHeader.size], &header.encode());
        @memcpy(self.write_buf[proto.MessageHeader.size..end], msg);

        // setup our to_write slice
        self.to_write = self.write_buf[0..end];

        // immediately write what we can
        return self.write();
    }

    // Returns `false` if we didn't manage to write the whole mssage
    // Returns `true` if the message is fully written
    fn write(self: *Client) !void {
        var buf = self.to_write;
        defer self.to_write = buf;
        while (buf.len > 0) {
            const n = posix.write(self.socket, buf) catch |err| switch (err) {
                error.WouldBlock => return self.loop.writeMode(self),
                else => return err,
            };

            if (n == 0) {
                return error.Closed;
            }
            buf = buf[n..];
        } else {
            return self.loop.readMode(self);
        }
    }

    fn handleMessage(self: *Client, m: proto.Message) !void {
        switch (m) {
            .Echo => |msg| std.debug.print("echo: {s}\n", .{msg}),
            .Ping => try self.writeProtoMessage(proto.Message{ .Pong = {} }),
            .clientKey => |pub_key| {
                log.debug("Received client key: {x:0>2}\n", .{pub_key});
                const sk = try Crypto.DH(self.kp, pub_key);
                self.reader.session = enc.init(alloc, "client-srv", sk, self.kp);
                self.reader.encryption = true;
            },
            else => unreachable,
        }
    }
};

const Reader = struct {
    buf: []u8,
    pos: usize = 0,
    start: usize = 0,
    encryption: bool = false,
    session: enc.Session = undefined,

    fn init(allocator: Allocator, size: usize) !Reader {
        const buf = try allocator.alloc(u8, size);
        return .{
            .pos = 0,
            .start = 0,
            .buf = buf,
        };
    }

    fn deinit(self: *const Reader, allocator: Allocator) void {
        allocator.free(self.buf);
    }

    fn readMessage(self: *Reader, socket: posix.socket_t) !proto.Message {
        var buf = self.buf;

        while (true) {
            if (try self.bufferedMessage()) |msg| {
                return msg;
            }
            const pos = self.pos;
            const n = try posix.read(socket, buf[pos..]);
            if (n == 0) {
                return error.Closed;
            }
            self.pos = pos + n;
        }
    }

    fn bufferedMessage(self: *Reader) !?proto.Message {
        const buf = self.buf;
        const pos = self.pos;
        const start = self.start;

        std.debug.assert(pos >= start);
        const unprocessed = buf[start..pos];

        if (unprocessed.len < proto.MessageHeader.size) {
            self.ensureSpace(proto.MessageHeader.size - unprocessed.len) catch unreachable;
            return null;
        }

        const h = try readHeader(unprocessed);
        const header_size = switch (h) {
            .base => proto.MessageHeader.size,
            .enc => proto.EncMessageHeader.size,
        };

        const message_len = switch (h) {
            .base => |b| b.length,
            .enc => |e| e.length,
        };

        // the length of our message + the length of our header
        const total_len = message_len + header_size;

        if (unprocessed.len < total_len) {
            try self.ensureSpace(total_len);
            return null;
        }

        self.start += total_len;

        const plain = unprocessed[header_size..total_len];
        const payload = switch (h) {
            .base => plain,
            .enc => |e| try self.session.RatchetDecrypt(.{ .ciphertext = plain, .header = .{ .DH = e.dh, .N = e.n, .PN = e.pn } }),
        };

        return proto.Message.parse(payload);
    }

    fn ensureSpace(self: *Reader, space: usize) error{BufferTooSmall}!void {
        const buf = self.buf;
        if (buf.len < space) {
            return error.BufferTooSmall;
        }

        const start = self.start;
        const spare = buf.len - start;
        if (spare >= space) {
            return;
        }

        const unprocessed = buf[start..self.pos];
        std.mem.copyForwards(u8, buf[0..unprocessed.len], unprocessed);
        self.start = 0;
        self.pos = unprocessed.len;
    }

    fn readHeader(data: []u8) !union(enum) { base: proto.MessageHeader, enc: proto.EncMessageHeader } {
        var h = try proto.MessageHeader.decode(data);

        if (!h.isEncrypted())
            return .{ .base = h };

        return .{ .enc = proto.EncMessageHeader.decode(h, data[proto.MessageHeader.size..]) };
    }
};

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
