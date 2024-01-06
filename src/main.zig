const std = @import("std");
const testing = std.testing;
const http = std.http;
const HttpClient = @import("HttpClient.zig");

test "connect https" {
    const allocator = testing.allocator;
    var client = HttpClient{ .allocator = allocator };
    defer client.deinit();

    var file = try std.fs.cwd().openFile("urls.txt", .{});
    defer file.close();

    var buf_reader = std.io.bufferedReader(file.reader());
    var in_stream = buf_reader.reader();

    var buf: [1024]u8 = undefined;
    while (try in_stream.readUntilDelimiterOrEof(&buf, '\n')) |line| {
        const uri = try std.Uri.parse(line);
        var headers = http.Headers{ .allocator = allocator };
        defer headers.deinit();

        var req = try client.open(.GET, uri, headers, .{});
        defer req.deinit();

        try req.send(.{ .raw_uri = true });
        try req.wait();
        const body = try req.reader().readAllAlloc(allocator, 1024 * 1024);
        defer allocator.free(body);

        std.debug.print("\n{s}: {s}", .{ line, std.fmt.fmtSliceEscapeLower(body[0..128]) });
    }
}
