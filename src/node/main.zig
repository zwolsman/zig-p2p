const std = @import("std");
const net = std.net;
const posix = std.posix;
const system = std.posix.system;
const Allocator = std.mem.Allocator;

const log = std.log.scoped(.tcp_demo);
const addr = std.net.Address.parseIp("0.0.0.0", 5882) catch unreachable;
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const alloc = gpa.allocator();

pub fn main() !void {
    var server = Server.init(alloc, 4096) catch {
        log.err("Could not initialise server", .{});
        return;
    };

    var serverThread = try std.Thread.spawn(.{}, runServer, .{&server});
    serverThread.detach();

    var stream: net.Stream = undefined;

    while (true) {
        stream = net.tcpConnectToAddress(addr) catch |err| {
            log.warn("Could not connect: {}\n", .{err});
            continue;
        };
        break;
    }

    log.info("Connected to server\n", .{});

    var client = try Client.init(alloc, stream.handle, addr, &server.loop);

    const in = std.io.getStdIn().reader();

    while (true) {
        std.debug.print("in: ", .{});
        var read_buf: [4096]u8 = undefined;
        const msg = try in.readUntilDelimiter(&read_buf, '\n');

        client.writeMessage(msg) catch |err| {
            log.err("Could not write msg: {}\n", .{err});
            continue;
        };

        const revc = client.readMessage() catch |err| {
            log.err("Could not read msg: {}\n", .{err});
            continue;
        };

        if (revc) |r| {
            std.debug.print("revc: {s}\n", .{r});
        }
    }
}

fn runServer(server: *Server) void {
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

                                client.read_timeout = std.time.milliTimestamp() + READ_TIMEOUT_MS;
                                read_timeout_list.remove(client.read_timeout_node);
                                read_timeout_list.append(client.read_timeout_node);
                                client.writeMessage(msg) catch {
                                    self.closeClient(client);
                                    break;
                                };
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

            const client = try self.client_pool.create();
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
        };
    }

    fn deinit(self: *const Client, allocator: Allocator) void {
        self.reader.deinit(allocator);
        allocator.free(self.write_buf);
    }

    fn readMessage(self: *Client) !?[]const u8 {
        return self.reader.readMessage(self.socket) catch |err| switch (err) {
            error.WouldBlock => return null,
            else => return err,
        };
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

        if (msg.len + 4 > self.write_buf.len) {
            // Could allocate a dynamic buffer. Could use a large buffer pool.
            return error.MessageTooLarge;
        }

        // copy our length prefix + message to our buffer
        std.mem.writeInt(u32, self.write_buf[0..4], @intCast(msg.len), .little);
        const end = msg.len + 4;
        @memcpy(self.write_buf[4..end], msg);

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
};

const Reader = struct {
    buf: []u8,
    pos: usize = 0,
    start: usize = 0,

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

    fn readMessage(self: *Reader, socket: posix.socket_t) ![]u8 {
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

    fn bufferedMessage(self: *Reader) !?[]u8 {
        const buf = self.buf;
        const pos = self.pos;
        const start = self.start;

        std.debug.assert(pos >= start);
        const unprocessed = buf[start..pos];

        if (unprocessed.len < 4) {
            self.ensureSpace(4 - unprocessed.len) catch unreachable;
            return null;
        }

        const message_len = std.mem.readInt(u32, unprocessed[0..4], .little);

        // the length of our message + the length of our prefix
        const total_len = message_len + 4;

        if (unprocessed.len < total_len) {
            try self.ensureSpace(total_len);
            return null;
        }

        self.start += total_len;
        return unprocessed[4..total_len];
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
