# Zig-TLS12

HTTP client capable of TLS 1.2.

You may use `HttpClient` in the same way you use `std.http.Client`.
The only difference of `HttpClient` from `std.http.Client` is that `std.crypto.tls.Client` which supports TLS 1.3 is replaced by a TLS 1.2 capable `TlsClient`.

## Example

This is tested againt zig version `0.12.0-dev.2059+42389cb9c`. Zig's HTTP interface has changed so it DOES NOT WORK on 0.11 and below.

```zig
const std = @import("std");
const HttpClient = @import("HttpClient.zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var client = HttpClient{ .allocator = allocator };
    defer client.deinit();
    try client.loadDefaultProxies();

    const url = "https://bing.com";

    const uri = try std.Uri.parse(url);
    var headers = std.http.Headers{ .allocator = allocator };
    defer headers.deinit();

    var req = try client.open(.GET, uri, headers, .{ .max_redirects = 10 });
    defer req.deinit();

    try req.send(.{ .raw_uri = true });
    try req.wait();
    const body = try req.reader().readAllAlloc(allocator, 16 * 1024 * 1024);
    defer allocator.free(body);

    std.debug.print("{s}: {s}\n", .{ url, body });
}
```
