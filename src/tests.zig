const std = @import("std");
const testing = std.testing;
const http = std.http;
const HttpClient = @import("HttpClient.zig");

test "Connect https" {
    const allocator = testing.allocator;
    var client = HttpClient{ .allocator = allocator };
    defer client.deinit();
    try client.loadDefaultProxies();

    var buf: [256]u8 = undefined;
    const url = try std.io.getStdIn().reader().readUntilDelimiter(&buf, '\n');

    const uri = try std.Uri.parse(url);
    var headers = http.Headers{ .allocator = allocator };
    defer headers.deinit();

    var req = try client.open(.GET, uri, headers, .{ .max_redirects = 10 });
    defer req.deinit();

    // The rest of a request lifecycle can be skipped for testing

    try req.send(.{});
    try req.wait();
    const body = try req.reader().readAllAlloc(allocator, 16 * 1024 * 1024);
    defer allocator.free(body);

    std.debug.print("\n{s}: {s}\n", .{ url, std.fmt.fmtSliceEscapeLower(body[0..128]) });
}
