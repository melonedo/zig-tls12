const std = @import("std");
const testing = std.testing;
const http = std.http;
const HttpClient = @import("HttpClient.zig");

test "connect https" {
    const allocator = testing.allocator;
    var client = HttpClient{ .allocator = allocator };
    defer client.deinit();
    const uri = try std.Uri.parse("https://bilibili.com/");
    var headers = http.Headers{ .allocator = allocator };
    defer headers.deinit();

    var req = try client.request(.GET, uri, headers, .{});
    defer req.deinit();

    try req.start();
    try req.wait();
    const body = try req.reader().readAllAlloc(allocator, 1024 * 32);
    defer allocator.free(body);

    std.debug.print("{s}", .{body});
}
