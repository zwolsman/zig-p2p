const std = @import("std");
const doubleratchet = @import("doubleratchet.zig");
const Crypto = @import("crypto.zig");

const net = std.net;
const addr = net.Address.initIp4(.{ 127, 0, 0, 1 }, 7496);

pub fn main() !void {
    // var server = try addr.listen(.{});

    // std.debug.print("Server is listening on: {any}\n", .{addr});
    // while (true) {
    //     const client = try server.accept();
    //     defer client.stream.close();

    //     const client_addr = client.address;
    //     std.debug.print("client addr is : {any}\n", .{client_addr});
    //     const th = try std.Thread.spawn(.{}, runEchoClient, .{client.stream});
    //     th.detach();
    // }

    const sk = [_]u8{
        0xeb, 0x8,  0x10, 0x7c, 0x33, 0x54, 0x0,  0x20,
        0xe9, 0x4f, 0x6c, 0x84, 0xe4, 0x39, 0x50, 0x5a,
        0x2f, 0x60, 0xbe, 0x81, 0xa,  0x78, 0x8b, 0xeb,
        0x1e, 0x2c, 0x9,  0x8d, 0x4b, 0x4d, 0xc1, 0x40,
    };

    const keypair = try Crypto.generateKeypair();

    std.debug.print("Generated new keypair.\nPub: {x:0>2}\nPriv: {x:0>2} \n", .{ keypair.public_key, keypair.secret_key });

    var bob = doubleratchet.init("bob", sk, keypair);

    var alice = try doubleratchet.initRemoteKey("alice", sk, keypair.public_key);

    const msg = try alice.RatchetEncrypt("Hi bob!");

    const result = try bob.RatchetDecrypt(msg);

    std.debug.print("Shared key: {x:0>2}\n\n", .{sk});
    std.debug.print("Bob pub: {x:0>2}\n", .{bob.state.DHr});
    std.debug.print("Alice pub: {x:0>2}\n\n", .{alice.state.DHr});
    std.debug.print("Message alice: {x:0>2}\n", .{msg.ciphertext});
    std.debug.print("Message bob: {s}\n\n", .{result});

    // const bobSaying = [_][]const u8{ "Hey Alice", "How are you doing", "Good to hear" };
    // const aliceSaying = [_][]const u8{ "Hey Bob", "I'm good!", "Anytime" };

    // for (bobSaying, aliceSaying) |b, a| {
    //     std.debug.print("Bobs key: {any}\n", .{bob.state.DHr});
    //     std.debug.print("Alices key: {any}\n", .{alice.state.DHr});

    //     const bobsEncryptedMessage = bob.RatchetEncrypt(b);
    //     std.debug.print("Bobs message: {any}\n", .{bobsEncryptedMessage});

    //     const aliceReceived = try alice.RatchetDecrypt(bobsEncryptedMessage);
    //     std.debug.print("Alice received: {s}\n", .{aliceReceived});

    //     const aliceEncryptedMessage = alice.RatchetEncrypt(a);
    //     std.debug.print("Alice message: {any}\n", .{aliceEncryptedMessage});

    //     const bobReceived = try bob.RatchetDecrypt(aliceEncryptedMessage);
    //     std.debug.print("Bob received: {s}\n", .{bobReceived});

    //     std.debug.print("\n\n", .{});
    // }
}

fn runEchoClient(conn: net.Stream) !void {
    while (true) {
        var buffer: [128]u8 = undefined;

        const len = try conn.read(&buffer);
        if (len == 0)
            break;
        // we ignore the amount of data sent.
        _ = try conn.write(buffer[0..len]);
    }
}
