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
const X25519 = std.crypto.dh.X25519;

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

    const keys = try X25519.KeyPair.create(null);
    const listen_address = try parseIpAddress(options.listen_address);

    var node: runtime.Node = try runtime.Node.init(alloc, keys, listen_address);

    log.debug("public key: {}", .{fmt.fmtSliceHexLower(&keys.public_key)});
    log.debug("secret key: {}", .{fmt.fmtSliceHexLower(&keys.secret_key)});

    try node.listen(listen_address);
    defer node.deinit();

    for (bootstrap_addresses.items) |bootstrap_address| {
        const address = try parseIpAddress(bootstrap_address);
        const client = try node.getOrCreateClient(address);
        log.info("connected to bootstrap node: {}", .{client.address});
    }

    if (options.interactive)
        openTty(&node);

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
                    std.debug.print("total peers connected to: {}", .{node.routing_table.len});
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
