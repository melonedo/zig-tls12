const std = @import("std");
const testing = std.testing;
const HttpClient = @import("HttpClient.zig");

test "Connect https" {
    const allocator = testing.allocator;
    var client = HttpClient{ .allocator = allocator };
    defer client.deinit();

    var buf: [256]u8 = undefined;
    const url = try std.io.getStdIn().reader().readUntilDelimiter(&buf, '\n');

    const uri = try std.Uri.parse(url);
    var headers = std.http.Headers{ .allocator = allocator };
    defer headers.deinit();
    var req = try client.request(.GET, uri, headers, .{});
    defer req.deinit();

    // The rest of a request lifecycle can be skipped for testing

    try req.start();
    try req.wait();
    const body = try req.reader().readAllAlloc(allocator, 16 * 1024 * 1024);
    defer allocator.free(body);

    std.debug.print("\n{s}: {s}\n", .{ url, std.fmt.fmtSliceEscapeLower(body[0..128]) });
}
