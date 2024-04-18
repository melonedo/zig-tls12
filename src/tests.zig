const std = @import("std");
const testing = std.testing;
const HttpClient = @import("HttpClient.zig");

test "Connect https" {
    const allocator = testing.allocator;
    var client = HttpClient{ .allocator = allocator };
    defer client.deinit();
    try client.initDefaultProxies(allocator);

    var buf: [256]u8 = undefined;
    const url = try std.io.getStdIn().reader().readUntilDelimiter(&buf, '\n');

    const uri = try std.Uri.parse(url);
    var server_header_buffer: [1024 * 1024]u8 = undefined;
    var req = try HttpClient.open(&client, .GET, uri, .{
        .server_header_buffer = &server_header_buffer,
        .redirect_behavior = @enumFromInt(10),
    });
    defer req.deinit();

    // The rest of a request lifecycle can be skipped for testing

    try req.send();
    try req.wait();
    const body = try req.reader().readAllAlloc(allocator, 16 * 1024 * 1024);
    defer allocator.free(body);

    std.debug.print("\n{s}: {s}\n", .{ url, std.fmt.fmtSliceEscapeLower(body[0..128]) });
}
