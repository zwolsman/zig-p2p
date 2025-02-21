const std = @import("std");
const net = std.net;
const posix = std.posix;
const system = std.posix.system;

const fmt = std.fmt;
const mem = std.mem;

const flags = @import("flags");
const CliFlags = @import("cliflags.zig");
const kademlia = @import("kademlia.zig");

const Allocator = std.mem.Allocator;
const Ed25519 = std.crypto.sign.Ed25519;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
var alloc = gpa.allocator();

const runtime = @import("runtime.zig");

pub fn main() !void {
    const log = std.log.scoped(.main);
    var args = try std.process.argsWithAllocator(alloc);
    defer args.deinit();

    var bootstrap_addresses = std.ArrayList([]const u8).init(gpa.allocator());
    defer bootstrap_addresses.deinit();

    const options = flags.parseOrExit(&args, "node", CliFlags, .{ .trailing_list = &bootstrap_addresses });

    const keys = try Ed25519.KeyPair.create(null);
    const listen_address = try parseIpAddress(options.listen_address);

    var node: runtime.Node = try runtime.Node.init(alloc, keys, listen_address);

    log.debug("public key: {}", .{fmt.fmtSliceHexLower(&keys.public_key.bytes)});
    log.debug("secret key: {}", .{fmt.fmtSliceHexLower(keys.secret_key.bytes[0..32])});

    try node.listen(listen_address);
    defer node.deinit();

    for (bootstrap_addresses.items) |bootstrap_address| {
        const address = try parseIpAddress(bootstrap_address);
        const client = try node.getOrCreateClient(address);
        log.info("connected to bootstrap node: {}", .{client.address});
    }

    try bootstrapNodeWithPeers(&node);

    if (options.interactive)
        openTty(&node);

    log.info("node is running", .{});
    try node.run();
}

fn openTty(n: *runtime.Node) void {
    const run = struct {
        const log = std.log.scoped(.tty);

        fn run(node: *runtime.Node) void {
            log.info("Opening interactive tty\n", .{});
            defer log.info("Closing interactive tty\n", .{});

            const r = std.io.getStdIn().reader();
            var buf: [1024]u8 = undefined;
            while (r.readUntilDelimiterOrEof(&buf, '\n') catch return) |txt| {
                if (std.mem.eql(u8, txt, "info")) {
                    std.debug.print("total peers connected to: {}\n", .{node.routing_table.len});
                }

                if (std.mem.startsWith(u8, txt, "route")) {
                    var public_key: [32]u8 = undefined;
                    _ = fmt.hexToBytes(&public_key, txt[6..70]) catch |err| {
                        log.warn("could convert to public key; {}", .{err});
                        continue;
                    };

                    std.debug.print("routing to {}\n", .{fmt.fmtSliceHexLower(&public_key)});
                    const peer_id = pid: {
                        if (node.routing_table.get(public_key)) |peer_id| {
                            break :pid peer_id;
                        }

                        var peer_ids: [16]runtime.ID = undefined;
                        const count = node.routing_table.closestTo(&peer_ids, public_key);
                        if (count == 0) {
                            log.warn("could not route packet to {}", .{fmt.fmtSliceHexLower(&public_key)});
                            continue;
                        }
                        break :pid peer_ids[0];
                    };

                    const client = node.getOrCreateClient(peer_id.address) catch |err| {
                        log.warn("couldn't create client ({}): {}", .{ peer_id, err });
                        continue;
                    };

                    (runtime.Packet{
                        .op = .command,
                        .tag = .route,
                    }).write(client.writer()) catch continue;
                    client.writer().writeAll(&node.id.public_key) catch continue;
                    client.writer().writeAll(&public_key) catch continue;

                    client.writer().writeInt(u8, 0, .little) catch continue;
                    client.write() catch continue;

                    std.debug.print("sent route cmd to {}\n", .{peer_id});
                }

                if (txt.len == 64) {
                    std.debug.print("looking up: {s}\n", .{txt});

                    var public_key: [32]u8 = undefined;
                    _ = fmt.hexToBytes(&public_key, txt) catch |err| {
                        log.warn("could convert to public key; {}", .{err});
                        continue;
                    };

                    if (std.mem.eql(u8, &node.id.public_key, &public_key)) {
                        std.debug.print("it's you!\n", .{});
                        continue;
                    }

                    if (node.routing_table.get(public_key)) |peer_id| {
                        std.debug.print("you're connected to it: {}\n", .{peer_id});
                        continue;
                    }

                    var peer_ids: [16]runtime.ID = undefined;
                    const node_count = node.routing_table.closestTo(&peer_ids, public_key);
                    std.debug.print("closest: {any}\n", .{peer_ids[0..node_count]});
                }
            }
        }
    }.run;

    const thread = std.Thread.spawn(.{}, run, .{n}) catch {
        std.debug.print("Could not open interactive tty\n", .{});
        return;
    };

    thread.detach();
}

fn parseIpAddress(address: []const u8) !net.Address {
    const parsed = splitHostPort(address) catch |err| return switch (err) {
        error.DelimiterNotFound => net.Address.parseIp("127.0.0.1", try fmt.parseUnsigned(u16, address, 10)),
        else => err,
    };

    const parsed_host = parsed.host;
    const parsed_port = try fmt.parseUnsigned(u16, parsed.port, 10);
    if (parsed_host.len == 0) return net.Address.parseIp("0.0.0.0", parsed_port);

    return net.Address.parseIp(parsed_host, parsed_port);
}

const HostPort = struct {
    host: []const u8,
    port: []const u8,
};

fn splitHostPort(address: []const u8) !HostPort {
    var j: usize = 0;
    var k: usize = 0;

    const i = mem.lastIndexOfScalar(u8, address, ':') orelse return error.DelimiterNotFound;

    const host = parse: {
        if (address[0] == '[') {
            const end = mem.indexOfScalar(u8, address, ']') orelse return error.MissingEndBracket;
            if (end + 1 == i) {} else if (end + 1 == address.len) {
                return error.MissingRightBracket;
            } else {
                return error.MissingPort;
            }

            j = 1;
            k = end + 1;
            break :parse address[1..end];
        }

        if (mem.indexOfScalar(u8, address[0..i], ':') != null) {
            return error.TooManyColons;
        }
        break :parse address[0..i];
    };

    if (mem.indexOfScalar(u8, address[j..], '[') != null) {
        return error.UnexpectedLeftBracket;
    }
    if (mem.indexOfScalar(u8, address[k..], ']') != null) {
        return error.UnexpectedRightBracket;
    }

    const port = address[i + 1 ..];

    return HostPort{ .host = host, .port = port };
}

fn bootstrapNodeWithPeers(node: *runtime.Node) !void {
    const log = std.log.scoped(.main);
    log.info("boostrapping node..", .{});

    var peer_ids: [16]runtime.ID = undefined;
    const count = node.routing_table.closestTo(&peer_ids, node.id.public_key);

    for (0..count) |i| {
        var client = try node.getOrCreateClient(peer_ids[i].address);
        try posix.setsockopt(client.socket, posix.SOL.SOCKET, posix.SOCK.NONBLOCK, &std.mem.toBytes(@as(c_int, 0)));

        log.debug("findings node by quering {?}", .{client.peer_id});
        try (runtime.Packet{
            .op = .request,
            .tag = .find_nodes,
        }).write(client.writer());

        try client.writer().writeAll(&node.id.public_key);
        try client.write();

        const response = try runtime.Packet.read(client.reader());
        switch (response.op) {
            .response => {
                switch (response.tag) {
                    .find_nodes => {
                        const len = try client.reader().readInt(u8, .little);
                        log.debug("{?} provided {} peers", .{ client.peer_id, len });
                        for (0..len) |_| {
                            const peer_id = runtime.ID.read(client.reader()) catch break;
                            _ = node.getOrCreateClient(peer_id.address) catch |err| {
                                log.warn("could not connect to {}, err: {}", .{ peer_id, err });
                                continue;
                            };
                        }
                    },
                    else => {
                        log.warn("unexpected tag {}", .{response.tag});
                        break;
                    },
                }
            },
            else => {
                log.warn("unexpected op {}", .{response.op});
                break;
            },
        }

        try posix.setsockopt(client.socket, posix.SOL.SOCKET, posix.SOCK.NONBLOCK, &std.mem.toBytes(@as(c_int, 1)));
    }
}

test "use X25519 to generate sk based on X25519 KeyPair" {
    const bob = try std.crypto.dh.X25519.KeyPair.create(null);
    const alice = try std.crypto.dh.X25519.KeyPair.create(null);
    std.log.debug("bob pub: {}", .{fmt.fmtSliceHexLower(&bob.public_key)});
    std.log.debug("bob priv: {}", .{fmt.fmtSliceHexLower(&bob.secret_key)});

    std.log.debug("alice pub: {}", .{fmt.fmtSliceHexLower(&alice.public_key)});
    std.log.debug("alice priv: {}", .{fmt.fmtSliceHexLower(&alice.secret_key)});

    const bob_secret = bob.secret_key;
    const alice_secret = alice.secret_key;
    const sk_bob = try std.crypto.dh.X25519.scalarmult(bob_secret, alice.public_key);
    const sk_alice = try std.crypto.dh.X25519.scalarmult(alice_secret, bob.public_key);

    std.log.debug("bob sk: {}", .{fmt.fmtSliceHexLower(&sk_bob)});
    std.log.debug("alice sk: {}", .{fmt.fmtSliceHexLower(&sk_alice)});
    try std.testing.expectEqualSlices(u8, &sk_bob, &sk_alice);
}
