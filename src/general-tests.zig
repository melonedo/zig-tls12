const std = @import("std");
const testing = std.testing;
const http = std.http;
const HttpClient = @import("HttpClient.zig");

// https://github.com/ziglang/zig/issues/17600
test "Record size limit 2^14" {
    const allocator = testing.allocator;
    // Cloudflare is more strict than httpbin.org
    const url = "https://api.cloudflare.com/client/v4" ++
        "/accounts/hello/workers/scripts/zigwasi?include_subdomain_availability=true&excludeScript=true";
    var headers = std.http.Headers.init(allocator);
    defer headers.deinit();
    try headers.append("Accept", "application/json");
    const request_payload_buffer = [_]u8{0xad} ** 66471;
    const request_payload = &request_payload_buffer;
    const cl = try std.fmt.allocPrint(allocator, "{d}", .{request_payload.len});
    defer allocator.free(cl);
    try headers.append("Content-Length", cl);
    var client = HttpClient{ .allocator = allocator };
    defer client.deinit();
    var req = try client.open(.PUT, try std.Uri.parse(url), headers, .{});
    defer req.deinit();

    req.transfer_encoding = .{ .content_length = @as(u64, request_payload.len) };
    try req.send(.{});
    try req.writeAll(request_payload);
    try req.finish();
    try req.wait();
    // We're literally just looking for a panic
}
