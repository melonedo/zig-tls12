const std = @import("std");
const HttpClient = @import("HttpClient.zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var client = HttpClient{ .allocator = allocator };
    defer client.deinit();

    const url = "https://httpbin.org";

    const uri = try std.Uri.parse(url);
    var headers = std.http.Headers{ .allocator = allocator };
    defer headers.deinit();
    var req = try client.request(.GET, uri, headers, .{});
    defer req.deinit();

    try req.start();
    try req.wait();
    const body = try req.reader().readAllAlloc(allocator, 16 * 1024 * 1024);
    defer allocator.free(body);

    std.debug.print("{s}: {s}\n", .{ url, body });
}
