const std = @import("std");
const Allocator = std.mem.Allocator;
const crypto = @import("crypto.zig");
const Key = crypto.Key;
const Crc32 = std.hash.crc.Crc32;

const MessageType = enum(u8) {
    Hello = 0x01,
    Ping = 0x02,
    Pong = 0x03,
    Echo = 0x04,
};

pub const MessageFlags = enum(u8) {
    none = 0b0000_0000, // 0x00
    encrypted = 0b0000_0001, // 0x01
    // Compressed = 0b0000_0010, // 0x02
    // Urgent = 0b0000_0100,     // 0x04

};

fn hasFlag(flags: u8, flag: MessageFlags) bool {
    return (flags & @intFromEnum(flag)) != 0;
}

fn setFlag(flags: *u8, flag: MessageFlags) void {
    flags.* |= @intFromEnum(flag);
}

fn clearFlag(flags: *u8, flag: MessageFlags) void {
    flags.* &= ~@intFromEnum(flag);
}

pub const MessageHeader = struct {
    length: u32, // Payload length
    crc: u32, // CRC32 for integrity
    flags: u8, // Encryption status, compression, etc.

    pub const size: usize = 4 + 4 + 1; // length + src + msg_type

    const Self = @This();

    fn init(
        length: u32,
        crc: u32,
        flags: u8,
    ) Self {
        return Self{ .length = length, .crc = crc, .flags = flags };
    }

    pub fn forMessage(data: []u8) Self {
        return Self{ .length = @intCast(data.len), .crc = Crc32.hash(data), .flags = 0x0 };
    }

    pub fn encode(self: Self) [size]u8 {
        var buff: [size]u8 = undefined;

        std.mem.writeInt(u32, buff[0..4], self.length, .little);
        std.mem.writeInt(u32, buff[4..8], self.crc, .little);
        buff[8] = self.flags;

        return buff;
    }

    pub fn decode(buff: []u8) !Self {
        return Self{
            .length = std.mem.readInt(u32, buff[0..4], .little),
            .crc = std.mem.readInt(u32, buff[4..8], .little),
            .flags = buff[8],
        };
    }

    pub fn isEncrypted(self: Self) bool {
        return hasFlag(self.flags, MessageFlags.encrypted);
    }
};

pub const EncMessageHeader = struct {
    length: u32,
    crc: u32,
    flags: u8,
    dh: Key,
    n: u32,
    pn: u32,

    const size = MessageHeader.size + Key.len + 4 + 4;

    const Self = @This();

    fn init(
        length: u32,
        crc: u32,
        flags: u8,
        dh: Key,
        n: u32,
        pn: u32,
    ) Self {
        if (!hasFlag(flags, MessageFlags.Encrypted)) {
            setFlag(&flags, MessageFlags.Encrypted);
        }

        return Self{ .length = length, .crc = crc, .flags = flags, .dh = dh, .n = n, .pn = pn };
    }

    fn encode(self: Self) [size]u8 {
        const base = MessageHeader.init(self.length, self.crc, self.flags).encode();
        const buffer = [Key.len + 4 + 4]u8;

        @memcpy(buffer[0..Key.len], self.dh);
        std.mem.writeInt(u32, buffer[Key.len .. Key.len + 4], self.n, .little);
        std.mem.writeInt(u32, buffer[Key.len + 4 ..], self.pn, .little);

        return base ++ buffer;
    }

    pub fn decode(h: MessageHeader, buff: []u8) Self {
        _ = h; // autofix
        _ = buff; // autofix
        unreachable;
    }
};

const Message = union(MessageType) {
    Hello: Key,
    Ping: void,
    Pong: void,
    Echo: []const u8,

    const Self = @This();

    fn encode(self: Self, allocator: Allocator) ![]u8 {
        var payload = std.ArrayList(u8).init(allocator);
        defer payload.deinit();

        _ = try payload.append(@intCast(@intFromEnum(self)));

        switch (self) {
            .Hello => |key| {
                _ = try payload.writer().writeAll(&key);
            },
            .Ping, .Pong => {},
            .Echo => |msg| {
                _ = try payload.writer().writeInt(u32, @intCast(msg.len), .little);
                _ = try payload.writer().writeAll(msg);
            },
        }

        return payload.toOwnedSlice();
    }

    fn decode() !Message {
        unreachable;
    }
};

pub fn hello(allocator: Allocator, pubKey: Key) ![]u8 {
    var msg = Message{ .Hello = pubKey };

    return msg.encode(allocator);
}

pub fn echo(allocator: Allocator, txt: []const u8) ![]u8 {
    var msg = Message{ .Echo = txt };

    return msg.encode(allocator);
}
