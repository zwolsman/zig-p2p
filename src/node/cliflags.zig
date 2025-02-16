//! config struct for the flags package argument parser
const CliFlags = @This();

// defaults:
addr: []const u8 = "127.0.0.1",
port: u16 = 5884,
node_addr: ?[]const u8 = null,
node_port: u16 = 5884,

pub const descriptions = .{
    .addr = "address to bind to (default: 127.0.0.1)",
    .port = "port to bind to (default: 5884)",
    .node_addr = "bootstrap node address (default:  null)",
    .node_port = "bootstrap node ip (default: 5884)",
};

pub const switches = .{
    .addr = 'a',
    .port = 'p',
};
