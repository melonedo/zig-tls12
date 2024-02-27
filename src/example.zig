const std = @import("std");
const HttpClient = @import("HttpClient.zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var client = HttpClient{ .allocator = allocator };
    defer client.deinit();
    try client.initDefaultProxies(allocator);

    const url = "https://bing.com";

    const uri = try std.Uri.parse(url);
    var server_header_buffer: [1024 * 1024]u8 = undefined;
    var req = try HttpClient.open(&client, .GET, uri, .{
        .server_header_buffer = &server_header_buffer,
        .redirect_behavior = @enumFromInt(10),
    });
    defer req.deinit();

    try req.send(.{});
    try req.wait();
    const body = try req.reader().readAllAlloc(allocator, 16 * 1024 * 1024);
    defer allocator.free(body);

    std.debug.print("{s}: {s}\n", .{ url, body });
}
