const std = @import("std");
pub fn main() !void {
    const value: u32 = 0x12345678; // Example u32 value

    // Create a pointer to the u32 value
    const bytePtr: *const u8 = @ptrCast(&value);
    _ = bytePtr; // autofix

    // Create an array to hold the bytes
    var bytes: [4]u8 = undefined;

    // Copy the bytes from the u32 value

    @memcpy(&bytes, std.mem.asBytes(&value));

    // Print the bytes
    for (bytes, 0..) |byte, index| {
        std.debug.print("Byte {}: {:#x}\n", .{ index, byte });
    }
}
