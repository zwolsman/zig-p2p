const std = @import("std");
const net = std.net;
const posix = std.posix;
const system = std.posix.system;

const fmt = std.fmt;
const mem = std.mem;

const flags = @import("flags");
const CliFlags = @import("cliflags.zig");

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

    try node.run();
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
