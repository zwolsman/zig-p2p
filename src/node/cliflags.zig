//! config struct for the flags package argument parser
const CliFlags = @This();

// defaults:
listen_address: []const u8 = "127.0.0.1:5884",
interactive: bool = false,

pub const descriptions = .{
    .listen_address = "Address to listen for peers on. [default: 127.0.0.1:5884]",
    .interactive = "Open a interactive tty [default: false]",
};

pub const switches = .{
    .listen_address = 'l',
    .interactive = 'i',
};
