const std = @import("std");
const net = std.net;
const addr = net.Address.initIp4(.{ 127, 0, 0, 1 }, 7496);

pub fn main() !void {
    std.debug.print("Client connecting to: {any}\n", .{addr});
    const conn = try net.tcpConnectToAddress(addr);

    try conn.writeAll("test");
    std.debug.print("Bye!\n", .{});
    defer conn.close();
}
