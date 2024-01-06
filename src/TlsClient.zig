const std = @import("std");
const tls = std.crypto.tls;
const Client = @This();
const net = std.net;
const mem = std.mem;
const crypto = std.crypto;
const assert = std.debug.assert;
const Certificate = @import("crypto/Certificate.zig");

const max_ciphertext_len = (1 << 14) + 2048;
const int2 = tls.int2;
const int3 = tls.int3;
const array = tls.array;
const enum_array = tls.enum_array;

read_seq: u64,
write_seq: u64,
/// The starting index of cleartext bytes inside `partially_read_buffer`.
partial_cleartext_idx: u15,
/// The ending index of cleartext bytes inside `partially_read_buffer` as well
/// as the starting index of ciphertext bytes.
partial_ciphertext_idx: u15,
/// The ending index of ciphertext bytes inside `partially_read_buffer`.
partial_ciphertext_end: u15,
/// When this is true, the stream may still not be at the end because there
/// may be data in `partially_read_buffer`.
received_close_notify: bool,
/// By default, reaching the end-of-stream when reading from the server will
/// cause `error.TlsConnectionTruncated` to be returned, unless a close_notify
/// message has been received. By setting this flag to `true`, instead, the
/// end-of-stream will be forwarded to the application layer above TLS.
/// This makes the application vulnerable to truncation attacks unless the
/// application layer itself verifies that the amount of data received equals
/// the amount of data expected, such as HTTP with the Content-Length header.
allow_truncation_attacks: bool = false,
application_cipher: ApplicationCipher,
/// The size is enough to contain exactly one TLSCiphertext record.
/// This buffer is segmented into four parts:
/// 0. unused
/// 1. cleartext
/// 2. ciphertext
/// 3. unused
/// The fields `partial_cleartext_idx`, `partial_ciphertext_idx`, and
/// `partial_ciphertext_end` describe the span of the segments.
/// .. |partial_cleartext_index| .. ciphertext .. |partial_ciphertext_idx| .. ciphertext .. |partial_ciphertext_end| ..
partially_read_buffer: [tls.max_ciphertext_record_len]u8,

// Actually, outside of `readvAdvaced` body, the `partially_read_buffer` may:
// 1. Contain only ciphertext, partial_cleartext_idx == partial_ciphertext_idx == 0
// 2. Contain only cleartext, partial_ciphertext_idx == partial_ciphertext_end
// 3. Contain both, partial_cleartext_idx < partial_ciphertext_idx < partial_ciphertext_end

/// `std.net.Stream` conforms to `std.crypto.tls.Client.StreamInterface`
pub const StreamInterface = std.crypto.tls.Client.StreamInterface;

pub fn makeClientHello(buf: []u8, host: []const u8, client_random: [32]u8, legacy_session_id: [32]u8) []const u8 {
    _ = legacy_session_id;
    const host_len: u16 = @intCast(host.len);
    const extensions_payload =
        tls.extension(.supported_versions, [_]u8{
        0x02, // byte length of supported versions
        0x03, 0x03, // TLS 1.2
    }) ++ tls.extension(.signature_algorithms, enum_array(tls.SignatureScheme, &.{
        .rsa_pkcs1_sha256,
        .rsa_pkcs1_sha384,
        .rsa_pkcs1_sha512,
    })) ++ tls.extension(.supported_groups, enum_array(tls.NamedGroup, &.{
        .secp256r1,
        .x25519,
    })) ++
        int2(@intFromEnum(tls.ExtensionType.server_name)) ++
        int2(host_len + 5) ++ // byte length of this extension payload
        int2(host_len + 3) ++ // server_name_list byte count
        [1]u8{0x00} ++ // name_type
        int2(host_len);

    const extensions_header =
        int2(@intCast(extensions_payload.len + host_len)) ++
        extensions_payload;

    const legacy_compression_methods = 0x0100;

    const client_hello =
        int2(@intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
        client_random ++
        [1]u8{0} ++
        cipher_suites ++
        int2(legacy_compression_methods) ++
        extensions_header;

    const out_handshake =
        [_]u8{@intFromEnum(tls.HandshakeType.client_hello)} ++
        int3(@intCast(client_hello.len + host_len)) ++
        client_hello;

    const plaintext_header = [_]u8{
        @intFromEnum(tls.ContentType.handshake),
        0x03, 0x01, // legacy_record_version
    } ++ int2(@intCast(out_handshake.len + host_len)) ++ out_handshake;

    @memcpy(buf[0..plaintext_header.len], &plaintext_header);
    return buf[0..plaintext_header.len];
}

/// Initiates a TLS handshake and establishes a TLSv1.2 session with `stream`.
///
/// `host` is only borrowed during this function call.
pub fn init(stream: std.net.Stream, ca_bundle: Certificate.Bundle, host: []const u8) !Client {
    var random_buffer: [128]u8 = undefined;
    crypto.random.bytes(&random_buffer);
    const client_random = random_buffer[0..32].*;
    const legacy_session_id = random_buffer[32..64].*;
    const x25519_kp_seed = random_buffer[64..96].*;
    const secp256r1_kp_seed = random_buffer[96..128].*;

    var hash: MessageHashType = undefined;
    var cipher: ApplicationCipher = undefined;

    const x25519_kp = crypto.dh.X25519.KeyPair.create(x25519_kp_seed) catch |err| switch (err) {
        // Only possible to happen if the private key is all zeroes.
        error.IdentityElement => return error.InsufficientEntropy,
    };
    const secp256r1_kp = crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.create(secp256r1_kp_seed) catch |err| switch (err) {
        // Only possible to happen if the private key is all zeroes.
        error.IdentityElement => return error.InsufficientEntropy,
    };

    // 256 is enough for TLS 1.2
    var buf: [256]u8 = undefined;
    const plaintext_header = makeClientHello(&buf, host, client_random, legacy_session_id);

    {
        var iovecs = [_]std.os.iovec_const{
            .{ .iov_base = plaintext_header.ptr, .iov_len = plaintext_header.len },
            .{ .iov_base = host.ptr, .iov_len = host.len },
        };
        try stream.writevAll(&iovecs);
    }

    const client_hello_bytes1 = plaintext_header[5..];
    var server_random: [32]u8 = undefined;

    var handshake_buffer: [8000]u8 = undefined;
    var d: tls.Decoder = .{ .buf = &handshake_buffer };
    var record_decoder: tls.Decoder = undefined;
    var cipher_suite_tag: CipherSuite = undefined;
    {
        try d.readAtLeastOurAmt(stream, tls.record_header_len);
        const ct = d.decode(tls.ContentType);
        d.skip(2); // legacy_record_version
        const record_len = d.decode(u16);
        try d.readAtLeast(stream, record_len);
        const server_hello_fragment = d.buf[d.idx..][0..record_len];
        record_decoder = try d.sub(record_len);
        switch (ct) {
            .alert => {
                try record_decoder.ensure(2);
                const level = record_decoder.decode(tls.AlertLevel);
                const desc = record_decoder.decode(tls.AlertDescription);
                _ = level;

                // if this isn't a error alert, then it's a closure alert, which makes no sense in a handshake
                try desc.toError();
                // TODO: handle server-side closures
                return error.TlsUnexpectedMessage;
            },
            .handshake => {},
            else => return error.TlsUnexpectedMessage,
        }
        try record_decoder.ensure(4);
        const handshake_type = record_decoder.decode(tls.HandshakeType);
        if (handshake_type != .server_hello) return error.TlsUnexpectedMessage;
        const length = record_decoder.decode(u24);
        var hsd = try record_decoder.sub(length);
        try hsd.ensure(2 + 32);
        const legacy_version = hsd.decode(u16);
        server_random = hsd.array(32).*;
        if (mem.eql(u8, &server_random, &tls.hello_retry_request_sequence)) {
            // This is a HelloRetryRequest message. This client implementation
            // does not expect to get one.
            return error.TlsUnexpectedMessage;
        }
        try hsd.ensure(1);
        const legacy_session_id_echo_len = hsd.decode(u8);
        try hsd.ensure(legacy_session_id_echo_len);
        const legacy_session_id_echo = hsd.slice(legacy_session_id_echo_len);
        try hsd.ensure(2 + 1);
        cipher_suite_tag = hsd.decode(CipherSuite);
        const hash_tag = messageHash(getAEAD(cipher_suite_tag));
        hash = switch (hash_tag) {
            .sha256 => MessageHashType{ .sha256 = crypto.hash.sha2.Sha256.init(.{}) },
            .sha384 => MessageHashType{ .sha384 = crypto.hash.sha2.Sha384.init(.{}) },
        };
        cipher = switch (getAEAD(cipher_suite_tag)) {
            inline .AES_128_GCM_SHA256,
            .AES_256_GCM_SHA384,
            .CHACHA20_POLY1305_SHA256,
            => |tag| createApplicationCipher(tag),
            else => unreachable,
        };
        switch (hash) {
            inline else => |*h| {
                h.update(client_hello_bytes1);
                h.update(host);
                h.update(server_hello_fragment);
            },
        }
        hsd.skip(1); // legacy_compression_method
        var extensions_size: u16 = 0;
        if (!hsd.eof()) {
            try hsd.ensure(2);
            extensions_size = hsd.decode(u16);
        }
        var all_extd = try hsd.sub(extensions_size);
        var supported_version: u16 = 0;
        const have_shared_key = false;
        while (!all_extd.eof()) {
            try all_extd.ensure(2 + 2);
            const et = all_extd.decode(tls.ExtensionType);
            const ext_size = all_extd.decode(u16);
            var extd = try all_extd.sub(ext_size);
            switch (et) {
                .supported_versions => {
                    if (supported_version != 0) return error.TlsIllegalParameter;
                    try extd.ensure(2);
                    supported_version = extd.decode(u16);
                },
                else => {},
            }
        }

        const tls_version = if (supported_version == 0) legacy_version else supported_version;
        if (tls_version == @intFromEnum(tls.ProtocolVersion.tls_1_3)) {
            if (!mem.eql(u8, legacy_session_id_echo, &legacy_session_id) or !have_shared_key)
                return error.TlsIllegalParameter;
        } else if (tls_version == @intFromEnum(tls.ProtocolVersion.tls_1_2)) {
            // try tls12.init(&stream, ca_bundle, host, @as(tls12.CipherSuite, @enumFromInt(@intFromEnum(cipher_suite_tag))), &d, &ptd, x25519_kp, secp256r1_kp, hello_rand, server_random);
        } else return error.TlsAlertProtocolVersion;
    }

    var main_cert_pub_key_algo: Certificate.AlgorithmCategory = undefined;
    var main_cert_pub_key_buf: [600]u8 = undefined;
    var main_cert_pub_key_len: u16 = undefined;

    // Server Certificate
    {
        try d.readAtLeastOurAmt(stream, tls.record_header_len);
        const ct = d.decode(tls.ContentType);
        if (ct != .handshake) return error.TlsUnexpectedMessage;
        const protocol_version = d.decode(u16);
        if (protocol_version != 0x0303) return error.TlsAlertProtocolVersion;
        const record_len = d.decode(u16);

        try d.readAtLeast(stream, record_len);
        switch (hash) {
            inline else => |*h| h.update(d.buf[d.idx..][0..record_len]),
        }
        var ptd = try d.sub(record_len);
        try ptd.ensure(4);
        const handshake_type = ptd.decode(HandshakeType);
        if (handshake_type != .certificate) return error.TlsUnexpectedMessage;
        const length = ptd.decode(u24);
        var hsd = try ptd.sub(length);
        try hsd.ensure(3);
        const certs_size = hsd.decode(u24);
        var certs_decoder = try hsd.sub(certs_size);

        var cert_index: usize = 0;
        var prev_cert: Certificate.Parsed = undefined;
        const now_sec = std.time.timestamp();
        while (!certs_decoder.eof()) {
            try certs_decoder.ensure(3);
            const cert_size = certs_decoder.decode(u24);
            const certd = try certs_decoder.sub(cert_size);

            const subject_cert: Certificate = .{
                .buffer = certd.buf,
                .index = @intCast(certd.idx),
            };
            const subject = try subject_cert.parse();

            if (cert_index == 0) {
                // Verify the host on the first certificate.
                try subject.verifyHostName(host);

                // Keep track of the public key for the
                // certificate_verify message later.
                main_cert_pub_key_algo = subject.pub_key_algo;
                const pub_key = subject.pubKey();
                if (pub_key.len > main_cert_pub_key_buf.len)
                    return error.CertificatePublicKeyInvalid;
                @memcpy(main_cert_pub_key_buf[0..pub_key.len], pub_key);
                main_cert_pub_key_len = @intCast(pub_key.len);
            } else {
                try prev_cert.verify(subject, now_sec);
            }

            if (ca_bundle.verify(subject, now_sec)) |_| {
                break;
            } else |err| switch (err) {
                error.CertificateIssuerNotFound => {},
                else => |e| return e,
            }

            prev_cert = subject;
            cert_index += 1;
        } else return error.TlsAlertUnknownCa;
    }

    // Server Key Exchange Message
    var shared_key: []const u8 = undefined;
    var named_group: tls.NamedGroup = undefined;
    {
        try d.readAtLeastOurAmt(stream, tls.record_header_len);
        const ct = d.decode(tls.ContentType);
        if (ct != .handshake) return error.TlsUnexpectedMessage;
        const protocol_version = d.decode(u16);
        if (protocol_version != 0x0303) return error.TlsAlertProtocolVersion;
        const record_len = d.decode(u16);
        try d.readAtLeast(stream, record_len);
        switch (hash) {
            inline else => |*h| h.update(d.buf[d.idx..][0..record_len]),
        }
        var ptd = try d.sub(record_len);
        try ptd.ensure(4);
        const handshake_type = ptd.decode(HandshakeType);
        if (handshake_type != .server_key_exchange) return error.TlsUnexpectedMessage;
        const length = ptd.decode(u24);
        var hsd = try ptd.sub(length);

        const is_ecc = is_ecdhe(cipher_suite_tag);
        // TODO: implement DHE
        assert(is_ecc);

        try hsd.ensure(4);
        const curve_type = hsd.decode(ECCurveType);
        if (curve_type != .named_curve) return error.TlsIllegalParameter;
        named_group = hsd.decode(tls.NamedGroup);
        const key_size = hsd.decode(u8);
        try hsd.ensure(key_size);
        const parameter_bytes = hsd.buf[hsd.idx - 4 ..][0 .. 4 + key_size];
        switch (named_group) {
            .x25519 => {
                const ksl = crypto.dh.X25519.public_length;
                if (key_size != ksl) return error.TlsIllegalParameter;
                const server_pub_key = hsd.array(ksl);

                shared_key = &(crypto.dh.X25519.scalarmult(
                    x25519_kp.secret_key,
                    server_pub_key.*,
                ) catch return error.TlsDecryptFailure);
            },
            .secp256r1 => {
                const server_pub_key = hsd.slice(key_size);

                const PublicKey = crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey;
                const pk = PublicKey.fromSec1(server_pub_key) catch {
                    return error.TlsDecryptFailure;
                };
                const mul = pk.p.mulPublic(secp256r1_kp.secret_key.bytes, .big) catch {
                    return error.TlsDecryptFailure;
                };
                shared_key = &mul.affineCoordinates().x.toBytes(.big);
            },
            else => {
                return error.TlsIllegalParameter;
            },
        }

        // verify certificate
        // TODO: RFC 7627 Extended Master Secret Extension
        try hsd.ensure(4);
        const scheme = hsd.decode(tls.SignatureScheme);
        const sig_len = hsd.decode(u16);
        try hsd.ensure(sig_len);
        const encoded_sig = hsd.slice(sig_len);
        const max_digest_len = 64;
        _ = max_digest_len;
        const main_cert_pub_key = main_cert_pub_key_buf[0..main_cert_pub_key_len];
        var verify_buf: [64 + 256]u8 = undefined;
        // TODO: figure out an upper bound
        assert(parameter_bytes.len < 256);
        @memcpy(verify_buf[0..32], &client_random);
        @memcpy(verify_buf[32..64], &server_random);
        @memcpy(verify_buf[64 .. 64 + parameter_bytes.len], parameter_bytes);
        const verify_bytes = verify_buf[0 .. 64 + parameter_bytes.len];

        switch (scheme) {
            inline .ecdsa_secp256r1_sha256,
            .ecdsa_secp384r1_sha384,
            => |comptime_scheme| {
                if (main_cert_pub_key_algo != .X9_62_id_ecPublicKey)
                    return error.TlsBadSignatureScheme;
                const Ecdsa = SchemeEcdsa(comptime_scheme);
                const sig = try Ecdsa.Signature.fromDer(encoded_sig);
                const key = try Ecdsa.PublicKey.fromSec1(main_cert_pub_key);
                try sig.verify(verify_bytes, key);
            },
            inline .rsa_pkcs1_sha1,
            .rsa_pkcs1_sha256,
            .rsa_pkcs1_sha384,
            .rsa_pkcs1_sha512,
            => |comptime_scheme| {
                const Hash = SchemeHash(comptime_scheme);
                try Certificate.verifyRsa(
                    Hash,
                    verify_bytes,
                    encoded_sig,
                    .rsaEncryption,
                    main_cert_pub_key,
                );
            },
            else => return error.TlsBadSignatureScheme,
        }
    }

    // Server Hello Done
    {
        try d.readAtLeastOurAmt(stream, tls.record_header_len);
        const ct = d.decode(tls.ContentType);
        if (ct != .handshake) return error.TlsUnexpectedMessage;
        const protocol_version = d.decode(u16);
        if (protocol_version != 0x0303) return error.TlsAlertProtocolVersion;
        const record_len = d.decode(u16);
        try d.readAtLeast(stream, record_len);
        switch (hash) {
            inline else => |*h| h.update(d.buf[d.idx..][0..record_len]),
        }
        var ptd = try d.sub(record_len);
        try ptd.ensure(4);
        const handshake_type = ptd.decode(HandshakeType);
        if (handshake_type != .server_hello_done) return error.TlsUnexpectedMessage;
        const length = ptd.decode(u24);
        if (length != 0) return error.TlsDecodeError;
    }

    // Client Key Exchange
    {
        const public_key: []const u8 = switch (named_group) {
            .x25519 => &x25519_kp.public_key,
            .secp256r1 => &secp256r1_kp.public_key.toUncompressedSec1(),
            else => unreachable,
        };
        const header = [1]u8{@intFromEnum(tls.ContentType.handshake)} ++
            tls.int2(@intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
            tls.int2(@intCast(public_key.len + 5)) ++
            [1]u8{@intFromEnum(HandshakeType.client_key_exchange)} ++
            tls.int3(@intCast(public_key.len + 1)) ++
            [1]u8{@intCast(public_key.len)};
        var iovecs = [_]std.os.iovec_const{
            .{ .iov_base = &header, .iov_len = header.len },
            .{ .iov_base = public_key.ptr, .iov_len = public_key.len },
        };
        try stream.writevAll(&iovecs);
        switch (hash) {
            inline else => |*h| {
                h.update(header[5..]);
                h.update(public_key);
            },
        }
    }

    // Client Change Cipher Spec
    {
        const record = [1]u8{@intFromEnum(tls.ContentType.change_cipher_spec)} ++
            tls.int2(@intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
            tls.int2(1) ++
            [1]u8{1};
        try stream.writeAll(&record);
    }

    // Calculate Keys
    var master_secret: [48]u8 = undefined;
    {
        const seed = client_random ++ server_random;
        master_secret = switch (hash) {
            inline else => |h| PRF(crypto.auth.hmac.Hmac(@TypeOf(h)), shared_key, "master secret", &seed, 48),
        };
        // Key Expansion: note that AEAD do not need mac key
        const seed2 = server_random ++ client_random;
        switch (cipher) {
            inline .AES_256_GCM_SHA384,
            .AES_128_GCM_SHA256,
            => |*c| {
                const aead = @TypeOf(c.*).AEAD;
                const nonce_len = aead.nonce_length - 8;
                const key_len = aead.key_length;
                const total_len = 2 * (key_len + nonce_len);
                const key_material = PRF(@TypeOf(c.*).Hmac, &master_secret, "key expansion", &seed2, total_len);
                c.client_key = key_material[0..key_len].*;
                c.server_key = key_material[key_len .. 2 * key_len].*;
                const iv_material = key_material[2 * key_len ..];
                c.client_iv[0..nonce_len].* = iv_material[0..nonce_len].*;
                c.server_iv = iv_material[nonce_len .. 2 * nonce_len].* ++ [1]u8{0} ** 8;
                // RFC 9325, Section 7.2.1
                // Add some entropy to the explicit IV as well
                var explicit_iv_mask: [8]u8 = undefined;
                crypto.random.bytes(&explicit_iv_mask);
                c.client_iv[nonce_len..].* = explicit_iv_mask;
            },
            .CHACHA20_POLY1305_SHA256 => {
                // TODO
                unreachable;
            },
        }
    }

    var client: Client = .{
        .read_seq = 0,
        .write_seq = 0,
        .partial_cleartext_idx = 0,
        .partial_ciphertext_idx = 0,
        .partial_ciphertext_end = 0,
        .received_close_notify = false,
        .application_cipher = cipher,
        .partially_read_buffer = undefined,
    };

    // Client Finished
    {
        const verify_data = switch (hash) {
            inline else => |*h| PRF(crypto.auth.hmac.Hmac(@TypeOf(h.*)), &master_secret, "client finished", &h.peek(), 12),
        };
        const handshake_finished: [16]u8 = [1]u8{@intFromEnum(HandshakeType.finished)} ++ int3(12) ++ verify_data;
        const total = try writeEnd(&client, stream, &handshake_finished, false, .handshake);
        assert(total == 16);
        switch (hash) {
            inline else => |*h| {
                h.update(&handshake_finished);
            },
        }
    }

    // Server Change Cipher Spec
    {
        try d.readAtLeastOurAmt(stream, tls.record_header_len);
        const ct = d.decode(tls.ContentType);
        if (ct != .change_cipher_spec) return error.TlsUnexpectedMessage;
        const protocol_version = d.decode(u16);
        if (protocol_version != 0x0303) return error.TlsAlertProtocolVersion;
        const record_len = d.decode(u16);
        if (record_len == 0) return error.TlsAlertUnexpectedMessage;
        try d.readAtLeast(stream, record_len);
        try d.ensure(record_len);
        _ = d.slice(record_len);
    }

    // Server Finished
    {
        const rest = d.rest();
        client.partial_ciphertext_end = @intCast(rest.len);
        @memcpy(client.partially_read_buffer[0..rest.len], rest);
        var handshake: [16]u8 = undefined;
        const total = try client.readAll(stream, &handshake);
        var ptd = tls.Decoder.fromTheirSlice(handshake[0..total]);
        try ptd.ensure(4);
        const handshake_type = ptd.decode(HandshakeType);
        if (handshake_type != .finished) return error.TlsUnexpectedMessage;
        const length = ptd.decode(u24);
        if (length != 12) return error.TlsDecodeError;
        try ptd.ensure(12);
        const server_verify = ptd.array(12);
        const verify_data = switch (hash) {
            inline else => |*h| PRF(crypto.auth.hmac.Hmac(@TypeOf(h.*)), &master_secret, "server finished", &h.finalResult(), 12),
        };
        if (!mem.eql(u8, server_verify, &verify_data))
            return error.TlsHandshakeFailure;
    }

    return client;
}

/// Sends TLS-encrypted data to `stream`, which must conform to `StreamInterface`.
/// Returns the number of plaintext bytes sent, which may be fewer than `bytes.len`.
pub fn write(c: *Client, stream: std.net.Stream, bytes: []const u8) !usize {
    return writeEnd(c, stream, bytes, false, .application_data);
}

/// Sends TLS-encrypted data to `stream`, which must conform to `StreamInterface`.
pub fn writeAll(c: *Client, stream: std.net.Stream, bytes: []const u8) !void {
    var index: usize = 0;
    while (index < bytes.len) {
        index += try c.write(stream, bytes[index..]);
    }
}

/// Sends TLS-encrypted data to `stream`, which must conform to `StreamInterface`.
/// If `end` is true, then this function additionally sends a `close_notify` alert,
/// which is necessary for the server to distinguish between a properly finished
/// TLS session, or a truncation attack.
pub fn writeAllEnd(c: *Client, stream: std.net.Stream, bytes: []const u8, end: bool) !void {
    var index: usize = 0;
    while (index < bytes.len) {
        index += try c.writeEnd(stream, bytes[index..], end, .application_data);
    }
}

/// Sends TLS-encrypted data to `stream`, which must conform to `StreamInterface`.
/// Returns the number of plaintext bytes sent, which may be fewer than `bytes.len`.
/// If `end` is true, then this function additionally sends a `close_notify` alert,
/// which is necessary for the server to distinguish between a properly finished
/// TLS session, or a truncation attack.
pub fn writeEnd(c: *Client, stream: std.net.Stream, bytes: []const u8, end: bool, inner_content_type: tls.ContentType) !usize {
    var ciphertext_buf: [tls.max_ciphertext_record_len * 4]u8 = undefined;
    var iovecs_buf: [6]std.os.iovec_const = undefined;
    var prepared = prepareCiphertextRecord(c, &iovecs_buf, &ciphertext_buf, bytes, inner_content_type);
    if (end) {
        prepared.iovec_end += prepareCiphertextRecord(
            c,
            iovecs_buf[prepared.iovec_end..],
            ciphertext_buf[prepared.ciphertext_end..],
            &tls.close_notify_alert,
            .alert,
        ).iovec_end;
    }

    const iovec_end = prepared.iovec_end;
    const overhead_len = prepared.overhead_len;

    // Ideally we would call writev exactly once here, however, we must ensure
    // that we don't return with a record partially written.
    var i: usize = 0;
    var total_amt: usize = 0;
    while (true) {
        var amt = try stream.writev(iovecs_buf[i..iovec_end]);
        while (amt >= iovecs_buf[i].iov_len) {
            const encrypted_amt = iovecs_buf[i].iov_len;
            total_amt += encrypted_amt - overhead_len;
            amt -= encrypted_amt;
            i += 1;
            // Rely on the property that iovecs delineate records, meaning that
            // if amt equals zero here, we have fortunately found ourselves
            // with a short read that aligns at the record boundary.
            if (i >= iovec_end) return total_amt;
            // We also cannot return on a vector boundary if the final close_notify is
            // not sent; otherwise the caller would not know to retry the call.
            if (amt == 0 and (!end or i < iovec_end - 1)) return total_amt;
        }
        iovecs_buf[i].iov_base += amt;
        iovecs_buf[i].iov_len -= amt;
    }
}

const CiphertextRecordResult = struct {
    iovec_end: usize,
    ciphertext_end: usize,
    /// How many bytes are taken up by overhead per record.
    overhead_len: usize,
};

fn prepareCiphertextRecord(
    c: *Client,
    iovecs: []std.os.iovec_const,
    ciphertext_buf: []u8,
    bytes: []const u8,
    inner_content_type: tls.ContentType,
) CiphertextRecordResult {
    var ciphertext_end: usize = 0;
    var iovec_end: usize = 0;
    var bytes_i: usize = 0;
    switch (c.application_cipher) {
        inline else => |*p| {
            const P = @TypeOf(p.*);
            const V = @Vector(P.AEAD.nonce_length, u8);
            const overhead_len = tls.record_header_len + P.explicit_nonce_len + P.AEAD.tag_length;
            const close_notify_alert_reserved = tls.close_notify_alert.len + overhead_len;
            while (true) {
                const encrypted_content_len: u16 = @intCast(@min(
                    @min(bytes.len - bytes_i, max_ciphertext_len),
                    ciphertext_buf.len - close_notify_alert_reserved -
                        overhead_len - ciphertext_end,
                ));
                if (encrypted_content_len == 0) return .{
                    .iovec_end = iovec_end,
                    .ciphertext_end = ciphertext_end,
                    .overhead_len = overhead_len,
                };

                const cleartext = bytes[bytes_i..][0..encrypted_content_len];
                bytes_i += encrypted_content_len;

                const record_start = ciphertext_end;
                const header = ciphertext_buf[ciphertext_end..][0..5];
                // length including nonce, data and tag (and padding)
                const full_length = P.explicit_nonce_len + encrypted_content_len + P.AEAD.tag_length;
                header.* =
                    [1]u8{@intFromEnum(inner_content_type)} ++
                    int2(@intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
                    int2(@intCast(full_length));
                ciphertext_end += header.len;
                const explicit_nonce = ciphertext_buf[ciphertext_end..][0..P.explicit_nonce_len];
                ciphertext_end += explicit_nonce.len;
                const ciphertext = ciphertext_buf[ciphertext_end..][0..encrypted_content_len];
                ciphertext_end += encrypted_content_len;
                const auth_tag = ciphertext_buf[ciphertext_end..][0..P.AEAD.tag_length];
                ciphertext_end += auth_tag.len;
                // The nonce for AEAD is always 4+8 bytes, whether the explicit part is send or not
                const pad = [1]u8{0} ** (P.AEAD.nonce_length - 8);
                const seq_big = @as([8]u8, @bitCast(big(c.write_seq)));
                const operand: V = pad ++ seq_big;
                c.write_seq += 1; // TODO send key_update on overflow
                const nonce = @as(V, p.client_iv) ^ operand;
                explicit_nonce.* = @as([12]u8, nonce)[12 - P.explicit_nonce_len .. 12].*;
                const ad = seq_big ++
                    [1]u8{@intFromEnum(inner_content_type)} ++
                    int2(@intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
                    int2(@intCast(encrypted_content_len));
                P.AEAD.encrypt(ciphertext, auth_tag, cleartext, &ad, nonce, p.client_key);

                const record = ciphertext_buf[record_start..ciphertext_end];
                iovecs[iovec_end] = .{
                    .iov_base = record.ptr,
                    .iov_len = record.len,
                };
                iovec_end += 1;
            }
        },
    }
}

pub fn eof(c: Client) bool {
    return c.received_close_notify and
        c.partial_cleartext_idx >= c.partial_ciphertext_idx and
        c.partial_ciphertext_idx >= c.partial_ciphertext_end;
}

/// Receives TLS-encrypted data from `stream`, which must conform to `StreamInterface`.
/// Returns the number of bytes read, calling the underlying read function the
/// minimal number of times until the buffer has at least `len` bytes filled.
/// If the number read is less than `len` it means the stream reached the end.
/// Reaching the end of the stream is not an error condition.
pub fn readAtLeast(c: *Client, stream: std.net.Stream, buffer: []u8, len: usize) !usize {
    var iovecs = [1]std.os.iovec{.{ .iov_base = buffer.ptr, .iov_len = buffer.len }};
    return readvAtLeast(c, stream, &iovecs, len);
}

/// Receives TLS-encrypted data from `stream`, which must conform to `StreamInterface`.
pub fn read(c: *Client, stream: std.net.Stream, buffer: []u8) !usize {
    return readAtLeast(c, stream, buffer, 1);
}

/// Receives TLS-encrypted data from `stream`, which must conform to `StreamInterface`.
/// Returns the number of bytes read. If the number read is smaller than
/// `buffer.len`, it means the stream reached the end. Reaching the end of the
/// stream is not an error condition.
pub fn readAll(c: *Client, stream: std.net.Stream, buffer: []u8) !usize {
    return readAtLeast(c, stream, buffer, buffer.len);
}

/// Receives TLS-encrypted data from `stream`, which must conform to `StreamInterface`.
/// Returns the number of bytes read. If the number read is less than the space
/// provided it means the stream reached the end. Reaching the end of the
/// stream is not an error condition.
/// The `iovecs` parameter is mutable because this function needs to mutate the fields in
/// order to handle partial reads from the underlying stream layer.
pub fn readv(c: *Client, stream: std.net.Stream, iovecs: []std.os.iovec) !usize {
    return readvAtLeast(c, stream, iovecs, 1);
}

/// Receives TLS-encrypted data from `stream`, which must conform to `StreamInterface`.
/// Returns the number of bytes read, calling the underlying read function the
/// minimal number of times until the iovecs have at least `len` bytes filled.
/// If the number read is less than `len` it means the stream reached the end.
/// Reaching the end of the stream is not an error condition.
/// The `iovecs` parameter is mutable because this function needs to mutate the fields in
/// order to handle partial reads from the underlying stream layer.
pub fn readvAtLeast(c: *Client, stream: std.net.Stream, iovecs: []std.os.iovec, len: usize) !usize {
    if (c.eof()) return 0;

    var off_i: usize = 0;
    var vec_i: usize = 0;
    while (true) {
        var amt = try c.readvAdvanced(stream, iovecs[vec_i..]);
        off_i += amt;
        if (c.eof() or off_i >= len) return off_i;
        while (amt >= iovecs[vec_i].iov_len) {
            amt -= iovecs[vec_i].iov_len;
            vec_i += 1;
        }
        iovecs[vec_i].iov_base += amt;
        iovecs[vec_i].iov_len -= amt;
    }
}

/// Receives TLS-encrypted data from `stream`, which must conform to `StreamInterface`.
/// Returns number of bytes that have been read, populated inside `iovecs`. A
/// return value of zero bytes does not mean end of stream. Instead, check the `eof()`
/// for the end of stream. The `eof()` may be true after any call to
/// `read`, including when greater than zero bytes are returned, and this
/// function asserts that `eof()` is `false`.
/// See `readv` for a higher level function that has the same, familiar API as
/// other read functions, such as `std.fs.File.read`.
pub fn readvAdvanced(c: *Client, stream: std.net.Stream, iovecs: []const std.os.iovec) !usize {
    var vp: VecPut = .{ .iovecs = iovecs };

    // Give away the buffered cleartext we have, if any.
    const partial_cleartext = c.partially_read_buffer[c.partial_cleartext_idx..c.partial_ciphertext_idx];
    if (partial_cleartext.len > 0) {
        const amt: u15 = @intCast(vp.put(partial_cleartext));
        c.partial_cleartext_idx += amt;

        if (c.partial_cleartext_idx == c.partial_ciphertext_idx and
            c.partial_ciphertext_end == c.partial_ciphertext_idx)
        {
            // The buffer is now empty.
            c.partial_cleartext_idx = 0;
            c.partial_ciphertext_idx = 0;
            c.partial_ciphertext_end = 0;
        }

        if (c.received_close_notify) {
            c.partial_ciphertext_end = 0;
            assert(vp.total == amt);
            return amt;
        } else if (amt > 0) {
            // We don't need more data, so don't call read.
            assert(vp.total == amt);
            return amt;
        }
    }
    assert(c.partial_cleartext_idx == 0 and c.partial_ciphertext_idx == 0);

    assert(!c.received_close_notify);

    // Ideally, this buffer would never be used. It is needed when `iovecs` are
    // too small to fit the cleartext, which may be as large as `max_ciphertext_len`.
    var cleartext_stack_buffer: [max_ciphertext_len]u8 = undefined;
    // Temporarily stores ciphertext before decrypting it and giving it to `iovecs`.
    var in_stack_buffer: [1]u8 = undefined;
    // How many bytes left in the user's buffer.
    const free_size = vp.freeSize();
    // The amount of the user's buffer that we need to repurpose for storing
    // ciphertext. The end of the buffer will be used for such purposes.
    const ciphertext_buf_len = (free_size / 2) -| in_stack_buffer.len;
    // The amount of the user's buffer that will be used to give cleartext. The
    // beginning of the buffer will be used for such purposes.
    const cleartext_buf_len = free_size - ciphertext_buf_len;
    // What do all above mean? Ciphertext is never stored in user's buffer.
    // And what does 4 ciphertext records mean?

    // Recoup `partially_read_buffer space`. This is necessary because it is assumed
    // below that `frag0` is big enough to hold at least one record.
    limitedOverlapCopy(c.partially_read_buffer[0..c.partial_ciphertext_end], c.partial_ciphertext_idx);
    c.partial_ciphertext_end -= c.partial_ciphertext_idx;
    c.partial_ciphertext_idx = 0;
    c.partial_cleartext_idx = 0;
    const remaining_partial_buffer = c.partially_read_buffer[c.partial_ciphertext_end..];

    var ask_iovecs_buf: [1]std.os.iovec = .{
        .{
            .iov_base = remaining_partial_buffer.ptr,
            .iov_len = remaining_partial_buffer.len,
        },
        // TODO: enable reading multiple records
        // .{
        //     .iov_base = &in_stack_buffer,
        //     .iov_len = in_stack_buffer.len,
        // },
    };

    // Cleartext capacity of output buffer, in records. Minimum one full record.
    const buf_cap = @max(cleartext_buf_len / max_ciphertext_len, 1);
    const wanted_read_len = buf_cap * (max_ciphertext_len + tls.record_header_len);
    const ask_len = @max(wanted_read_len, cleartext_stack_buffer.len);
    const ask_iovecs = limitVecs(&ask_iovecs_buf, ask_len);

    var actual_read_len: usize = 0;
    readv: {
        // Skip `stream.readv` if there is a complete record unprocessed
        // This may happen when different types of traffic are mixed.
        if (c.partial_ciphertext_end > 0) {
            const record_len = mem.readInt(u16, c.partially_read_buffer[3..5], .big);
            if (record_len + 5 <= c.partial_ciphertext_end)
                break :readv;
        }
        actual_read_len = try stream.readv(ask_iovecs);
        if (actual_read_len == 0) {
            // This is either a truncation attack, a bug in the server, or an
            // intentional omission of the close_notify message due to truncation
            // detection handled above the TLS layer.
            if (c.allow_truncation_attacks) {
                c.received_close_notify = true;
            } else {
                return error.TlsConnectionTruncated;
            }
        }
    }

    // There might be more bytes inside `in_stack_buffer` that need to be processed,
    // but at least frag0 will have one complete ciphertext record.
    const frag0_end = @min(c.partially_read_buffer.len, c.partial_ciphertext_end + actual_read_len);
    const frag0 = c.partially_read_buffer[c.partial_ciphertext_idx..frag0_end];
    var frag1 = in_stack_buffer[0..actual_read_len -| remaining_partial_buffer.len];
    // We need to decipher frag0 and frag1 but there may be a ciphertext record
    // straddling the boundary. We can handle this with two memcpy() calls to
    // assemble the straddling record in between handling the two sides.
    var frag = frag0;
    var in: usize = 0;
    while (true) {
        // Ensure `frag` has something unread.
        if (in == frag.len) {
            // Perfect split.
            if (frag.ptr == frag1.ptr) {
                // Buffer now contains only cleartext
                c.partial_ciphertext_end = c.partial_ciphertext_idx;
                return vp.total;
            }
            frag = frag1;
            in = 0;
            continue;
        }

        // Ensure a complete record header is in `frag` or finish.
        if (in + tls.record_header_len > frag.len) {
            if (finishRead(c, 0, frag, frag1, in)) return vp.total;

            // A record header straddles the two fragments. Copy into the now-empty first fragment.
            const record_len_byte_0: u16 = straddleByte(frag, frag1, in + 3);
            const record_len_byte_1: u16 = straddleByte(frag, frag1, in + 4);
            const record_len = (record_len_byte_0 << 8) | record_len_byte_1;
            if (record_len > max_ciphertext_len) return error.TlsRecordOverflow;

            const full_record_len = record_len + tls.record_header_len;
            const first = frag[in..];
            const second_len = full_record_len - first.len;
            if (frag1.len < second_len) {
                finishRead2(c, first, frag1);
                return vp.total;
            }
            limitedOverlapCopy(frag, in);
            @memcpy(frag[first.len..][0..second_len], frag1[0..second_len]);
            frag = frag[0..full_record_len];
            frag1 = frag1[second_len..];
            in = 0;
            continue;
        }

        // Ensure a complete record is in `frag`
        const ct: tls.ContentType = @enumFromInt(frag[in]);
        const legacy_version = mem.readInt(u16, frag[in..][1..3], .big);
        const record_len = mem.readInt(u16, frag[in..][3..5], .big);
        if (record_len > max_ciphertext_len) return error.TlsRecordOverflow;
        in += 5;
        const end = in + record_len;
        if (end > frag.len) {
            // We need the record header on the next iteration of the loop.
            in -= 5;

            if (finishRead(c, record_len, frag, frag1, in)) return vp.total;

            const full_record_len = record_len + tls.record_header_len;
            const first_len = frag.len - in;
            const second_len = full_record_len - first_len;
            limitedOverlapCopy(frag, in);
            @memcpy(frag[first_len..][0..second_len], frag1[0..second_len]);
            frag = frag[0..full_record_len];
            frag1 = frag1[second_len..];
            in = 0;
            continue;
        }

        // Now decode a complete record in `frag`
        switch (ct) {
            .alert => {
                if (in + 2 > frag.len) return error.TlsDecodeError;
                const level: tls.AlertLevel = @enumFromInt(frag[in]);
                const desc: tls.AlertDescription = @enumFromInt(frag[in + 1]);
                _ = level;

                try desc.toError();
                // TODO: handle server-side closures
                return error.TlsUnexpectedMessage;
            },
            .application_data, .handshake => {},
            else => return error.TlsUnexpectedMessage,
        }
        const cleartext = switch (c.application_cipher) {
            inline else => |*p| c: {
                const P = @TypeOf(p.*);
                const V = @Vector(P.AEAD.nonce_length, u8);
                const ciphertext_len = record_len - P.AEAD.tag_length - P.explicit_nonce_len;
                const explicit_nonce = frag[in..][0..P.explicit_nonce_len].*;
                in += explicit_nonce.len;
                const ciphertext = frag[in..][0..ciphertext_len];
                in += ciphertext_len;
                const auth_tag = frag[in..][0..P.AEAD.tag_length].*;
                const pad = [1]u8{0} ** (P.AEAD.nonce_length - 8);
                const seq_big = @as([8]u8, @bitCast(big(c.read_seq)));
                var nonce: [P.AEAD.nonce_length]u8 = undefined;
                if (explicit_nonce.len != 0) {
                    const implicit_nonce_len = P.AEAD.nonce_length - explicit_nonce.len;
                    nonce[0..implicit_nonce_len].* = p.server_iv[0..implicit_nonce_len].*;
                    nonce[implicit_nonce_len..P.AEAD.nonce_length].* = explicit_nonce;
                } else {
                    const operand: V = pad ++ seq_big;
                    nonce = @as(V, p.server_iv) ^ operand;
                }
                const out_buf = vp.peek();
                const cleartext_buf = if (ciphertext.len <= out_buf.len)
                    out_buf
                else
                    &cleartext_stack_buffer;
                const cleartext = cleartext_buf[0..ciphertext.len];
                const ad = seq_big ++
                    [1]u8{@intFromEnum(ct)} ++
                    int2(legacy_version) ++
                    int2(@intCast(ciphertext_len));
                P.AEAD.decrypt(cleartext, ciphertext, auth_tag, &ad, nonce, p.server_key) catch
                    return error.TlsBadRecordMac;
                break :c cleartext;
            },
        };

        c.read_seq = try std.math.add(u64, c.read_seq, 1);

        // Determine whether the output buffer or a stack
        // buffer was used for storing the cleartext.
        if (cleartext.ptr == &cleartext_stack_buffer) {
            // Stack buffer was used, so we must copy to the output buffer.
            if (c.partial_ciphertext_idx > c.partial_cleartext_idx) {
                // We have already run out of room in iovecs. Continue
                // appending to `partially_read_buffer`.
                @memcpy(
                    c.partially_read_buffer[c.partial_ciphertext_idx..][0..cleartext.len],
                    cleartext,
                );
                c.partial_ciphertext_idx = @intCast(c.partial_ciphertext_idx + cleartext.len);
            } else {
                const amt = vp.put(cleartext);
                if (amt < cleartext.len) {
                    const rest = cleartext[amt..];
                    c.partial_cleartext_idx = 0;
                    c.partial_ciphertext_idx = @intCast(rest.len);
                    @memcpy(c.partially_read_buffer[0..rest.len], rest);
                }
            }
        } else {
            // Output buffer was used directly which means no
            // memory copying needs to occur, and we can move
            // on to the next ciphertext record.
            vp.next(cleartext.len);
        }
        in = end;
    }
}

/// Finish reading by copying data from `frag` and `frag1` to `c.partilly_read_buffer`
/// Return whether `finishReadX` is called
/// If `record_len` is not know, it can be set to zero to only check for the header.
fn finishRead(c: *Client, record_len: usize, frag: []const u8, frag1: []const u8, index: usize) bool {
    if (frag.ptr == frag1.ptr) {
        finishRead1(c, frag, index);
        return true;
    }

    // A record straddles the two fragments. Copy into the now-empty first fragment.
    const first = frag[index..];
    const full_record_len = record_len + tls.record_header_len;
    const second_len = full_record_len - first.len;
    if (frag1.len < second_len) {
        finishRead2(c, first, frag1);
        return true;
    }
    return false;
}

/// Finish reading the in-stack buffer after reading all ciphtext from `c.partially_read_buffer`
fn finishRead1(c: *Client, frag: []const u8, in: usize) void {
    const saved_buf = frag[in..];
    if (c.partial_ciphertext_idx > c.partial_cleartext_idx) {
        // There is cleartext at the beginning already which we need to preserve.
        c.partial_ciphertext_end = @intCast(c.partial_ciphertext_idx + saved_buf.len);
        @memcpy(c.partially_read_buffer[c.partial_ciphertext_idx..][0..saved_buf.len], saved_buf);
    } else {
        c.partial_cleartext_idx = 0;
        c.partial_ciphertext_idx = 0;
        c.partial_ciphertext_end = @intCast(saved_buf.len);
        @memcpy(c.partially_read_buffer[0..saved_buf.len], saved_buf);
    }
}

/// Finish reading both the in-stack buffer and `c.partially_read_buffer`
/// Note that `first` usually overlaps with `c.partially_read_buffer`.
fn finishRead2(c: *Client, first: []const u8, second: []const u8) void {
    if (c.partial_ciphertext_idx > c.partial_cleartext_idx) {
        // There is cleartext at the beginning already which we need to preserve.
        c.partial_ciphertext_end = @intCast(c.partial_ciphertext_idx + first.len + second.len);
        // TODO: eliminate this call to copyForwards
        std.mem.copyForwards(u8, c.partially_read_buffer[c.partial_ciphertext_idx..][0..first.len], first);
        @memcpy(c.partially_read_buffer[c.partial_ciphertext_idx + first.len ..][0..second.len], second);
    } else {
        c.partial_cleartext_idx = 0;
        c.partial_ciphertext_idx = 0;
        c.partial_ciphertext_end = @intCast(first.len + second.len);
        // TODO: eliminate this call to copyForwards
        std.mem.copyForwards(u8, c.partially_read_buffer[0..first.len], first);
        @memcpy(c.partially_read_buffer[first.len..][0..second.len], second);
    }
}

/// Move `frag[in..]` to the beggining of `frag`
fn limitedOverlapCopy(frag: []u8, in: usize) void {
    const first = frag[in..];
    if (first.len <= in) {
        // A single, non-overlapping memcpy suffices.
        @memcpy(frag[0..first.len], first);
    } else {
        // One memcpy call would overlap, so just do this instead.
        std.mem.copyForwards(u8, frag, first);
    }
}

fn straddleByte(s1: []const u8, s2: []const u8, index: usize) u8 {
    if (index < s1.len) {
        return s1[index];
    } else {
        return s2[index - s1.len];
    }
}

const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();

inline fn big(x: anytype) @TypeOf(x) {
    return switch (native_endian) {
        .big => x,
        .little => @byteSwap(x),
    };
}

pub fn SchemeEcdsa(comptime scheme: tls.SignatureScheme) type {
    return switch (scheme) {
        .ecdsa_secp256r1_sha256 => crypto.sign.ecdsa.EcdsaP256Sha256,
        .ecdsa_secp384r1_sha384 => crypto.sign.ecdsa.EcdsaP384Sha384,
        .ecdsa_secp521r1_sha512 => crypto.sign.ecdsa.EcdsaP512Sha512,
        else => @compileError("bad scheme"),
    };
}

pub fn SchemeHash(comptime scheme: tls.SignatureScheme) type {
    return switch (scheme) {
        .rsa_pss_rsae_sha256 => crypto.hash.sha2.Sha256,
        .rsa_pss_rsae_sha384 => crypto.hash.sha2.Sha384,
        .rsa_pss_rsae_sha512 => crypto.hash.sha2.Sha512,

        .rsa_pkcs1_sha1 => crypto.hash.Sha1,
        .rsa_pkcs1_sha256 => crypto.hash.sha2.Sha256,
        .rsa_pkcs1_sha384 => crypto.hash.sha2.Sha384,
        .rsa_pkcs1_sha512 => crypto.hash.sha2.Sha512,
        else => @compileError("bad scheme"),
    };
}

pub const HashName = enum {
    // sha1,
    sha256,
    sha384,
    // sha512,
};

pub const MessageHashType = union(HashName) {
    // sha1: crypto.hash.Sha1,
    sha256: crypto.hash.sha2.Sha256,
    sha384: crypto.hash.sha2.Sha384,
    // sha512: crypto.hash.sha2.Sha512,
};

/// Abstraction for sending multiple byte buffers to a slice of iovecs.
const VecPut = struct {
    iovecs: []const std.os.iovec,
    idx: usize = 0,
    off: usize = 0,
    total: usize = 0,

    /// Returns the amount actually put which is always equal to bytes.len
    /// unless the vectors ran out of space.
    fn put(vp: *VecPut, bytes: []const u8) usize {
        if (vp.idx >= vp.iovecs.len) return 0;
        var bytes_i: usize = 0;
        while (true) {
            const v = vp.iovecs[vp.idx];
            const dest = v.iov_base[vp.off..v.iov_len];
            const src = bytes[bytes_i..][0..@min(dest.len, bytes.len - bytes_i)];
            @memcpy(dest[0..src.len], src);
            bytes_i += src.len;
            vp.off += src.len;
            if (vp.off >= v.iov_len) {
                vp.off = 0;
                vp.idx += 1;
                if (vp.idx >= vp.iovecs.len) {
                    vp.total += bytes_i;
                    return bytes_i;
                }
            }
            if (bytes_i >= bytes.len) {
                vp.total += bytes_i;
                return bytes_i;
            }
        }
    }

    /// Returns the next buffer that consecutive bytes can go into.
    fn peek(vp: VecPut) []u8 {
        if (vp.idx >= vp.iovecs.len) return &.{};
        const v = vp.iovecs[vp.idx];
        return v.iov_base[vp.off..v.iov_len];
    }

    // After writing to the result of peek(), one can call next() to
    // advance the cursor.
    fn next(vp: *VecPut, len: usize) void {
        vp.total += len;
        vp.off += len;
        if (vp.off >= vp.iovecs[vp.idx].iov_len) {
            vp.off = 0;
            vp.idx += 1;
        }
    }

    fn freeSize(vp: VecPut) usize {
        if (vp.idx >= vp.iovecs.len) return 0;
        var total: usize = 0;
        total += vp.iovecs[vp.idx].iov_len - vp.off;
        if (vp.idx + 1 >= vp.iovecs.len) return total;
        for (vp.iovecs[vp.idx + 1 ..]) |v| total += v.iov_len;
        return total;
    }
};

/// Limit iovecs to a specific byte size.
fn limitVecs(iovecs: []std.os.iovec, len: usize) []std.os.iovec {
    var bytes_left: usize = len;
    for (iovecs, 0..) |*iovec, vec_i| {
        if (bytes_left <= iovec.iov_len) {
            iovec.iov_len = bytes_left;
            return iovecs[0 .. vec_i + 1];
        }
        bytes_left -= iovec.iov_len;
    }
    return iovecs;
}

pub const cipher_suites = tls.enum_array(CipherSuite, &.{
    // .DHE_RSA_WITH_AES_128_GCM_SHA256,
    .ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    // .DHE_PSK_WITH_AES_128_GCM_SHA256,
    // .ECDHE_PSK_WITH_AES_128_GCM_SHA256,
    .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    // .DHE_RSA_WITH_AES_256_GCM_SHA384,
    .ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    // .DHE_PSK_WITH_AES_256_GCM_SHA384,
    // .ECDHE_PSK_WITH_AES_256_GCM_SHA384,
    .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    // .DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    // .DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
    // .ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
    .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
});

pub const CipherSuite = enum(u16) {
    // TLS 1.2 cipher suites equivalent to ones supported by TLS 1.3
    // Key exchange: DHE/ECDHE
    // Authentication: RSA/PSK/ECDSA(only with ECDHE)
    // AEAD: AES_128_GCM_SHA256/AES_256_GCM_SHA384/CHACHA20_POLY1305_SHA256
    DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x009e,
    DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x009f,
    DHE_PSK_WITH_AES_128_GCM_SHA256 = 0x00aa,
    DHE_PSK_WITH_AES_256_GCM_SHA384 = 0x00ab,
    ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02b,
    ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02c,
    ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f,
    ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xc030,
    ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca8,
    ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca9,
    DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xccaa,
    ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xccac,
    DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xccad,
    ECDHE_PSK_WITH_AES_128_GCM_SHA256 = 0xd001,
    ECDHE_PSK_WITH_AES_256_GCM_SHA384 = 0xd002,
    _,
};

pub const HandshakeType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate = 11,
    server_key_exchange = 12,
    certificate_request = 13,
    server_hello_done = 14,
    certificate_verify = 15,
    client_key_exchange = 16,
    finished = 20,
    key_update = 24,
    message_hash = 254,
    _,
};

pub const ECCurveType = enum(u8) {
    explicit_prime = 1, // deprecated by RFC 8422
    explicit_char2 = 2, // deprecated by RFC 8422
    named_curve = 3,
    _,
};

pub const ECPointFormat = enum(u8) {
    uncompressed = 0,
    ansiX962_compressed_prime = 1, // deprecated by RFC 8422
    ansiX962_compressed_char2 = 2, // deprecated by RFC 8422
    _,
};

pub fn getAEAD(cs: CipherSuite) tls.CipherSuite {
    return switch (cs) {
        .DHE_RSA_WITH_AES_128_GCM_SHA256 => .AES_128_GCM_SHA256,
        .ECDHE_RSA_WITH_AES_128_GCM_SHA256 => .AES_128_GCM_SHA256,
        .DHE_PSK_WITH_AES_128_GCM_SHA256 => .AES_128_GCM_SHA256,
        .ECDHE_PSK_WITH_AES_128_GCM_SHA256 => .AES_128_GCM_SHA256,
        .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => .AES_128_GCM_SHA256,
        .DHE_RSA_WITH_AES_256_GCM_SHA384 => .AES_256_GCM_SHA384,
        .ECDHE_RSA_WITH_AES_256_GCM_SHA384 => .AES_256_GCM_SHA384,
        .DHE_PSK_WITH_AES_256_GCM_SHA384 => .AES_256_GCM_SHA384,
        .ECDHE_PSK_WITH_AES_256_GCM_SHA384 => .AES_256_GCM_SHA384,
        .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => .AES_256_GCM_SHA384,
        .DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => .CHACHA20_POLY1305_SHA256,
        .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => .CHACHA20_POLY1305_SHA256,
        .DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 => .CHACHA20_POLY1305_SHA256,
        .ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 => .CHACHA20_POLY1305_SHA256,
        .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => .CHACHA20_POLY1305_SHA256,
        else => unreachable,
    };
}

pub fn messageHash(cs: tls.CipherSuite) HashName {
    return switch (cs) {
        .AES_128_GCM_SHA256 => .sha256,
        .AES_256_GCM_SHA384 => .sha384,
        .CHACHA20_POLY1305_SHA256 => .sha256,
        else => unreachable,
    };
}

pub fn ApplicationCipherT(comptime AeadType: type, comptime HashType: type, comptime explicit_nonce: usize) type {
    return struct {
        pub const AEAD = AeadType;
        pub const Hash = HashType;
        pub const Hmac = crypto.auth.hmac.Hmac(Hash);
        pub const explicit_nonce_len = explicit_nonce;

        client_key: [AEAD.key_length]u8,
        server_key: [AEAD.key_length]u8,
        // For AES_GCM in TLS 1.2, lower 8 bytes are explicit nonce
        client_iv: [AEAD.nonce_length]u8,
        server_iv: [AEAD.nonce_length]u8,
    };
}

/// Encryption parameters for application traffic.
pub const ApplicationCipher = union(enum) {
    AES_128_GCM_SHA256: ApplicationCipherT(crypto.aead.aes_gcm.Aes128Gcm, crypto.hash.sha2.Sha256, 8),
    AES_256_GCM_SHA384: ApplicationCipherT(crypto.aead.aes_gcm.Aes256Gcm, crypto.hash.sha2.Sha384, 8),
    CHACHA20_POLY1305_SHA256: ApplicationCipherT(crypto.aead.chacha_poly.ChaCha20Poly1305, crypto.hash.sha2.Sha256, 0),
};

pub fn createApplicationCipher(comptime tag: tls.CipherSuite) ApplicationCipher {
    return @unionInit(ApplicationCipher, @tagName(tag), .{
        .client_key = undefined,
        .server_key = undefined,
        .client_iv = undefined,
        .server_iv = undefined,
    });
}

fn is_ecdhe(cs: CipherSuite) bool {
    return switch (cs) {
        .ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        .ECDHE_PSK_WITH_AES_128_GCM_SHA256,
        .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        .ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        .ECDHE_PSK_WITH_AES_256_GCM_SHA384,
        .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        .ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
        .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        => true,
        .DHE_RSA_WITH_AES_128_GCM_SHA256,
        .DHE_PSK_WITH_AES_128_GCM_SHA256,
        .DHE_RSA_WITH_AES_256_GCM_SHA384,
        .DHE_PSK_WITH_AES_256_GCM_SHA384,
        .DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        .DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
        => false,
        _ => unreachable,
    };
}

pub fn read_single_record(stream: *const std.net.Stream, stream_decoder: *tls.Decoder, record_decoder: *tls.Decoder, content_type: tls.ContentType, handshake_type: HandshakeType) !tls.Decoder {
    if (record_decoder.eof()) {
        try stream_decoder.readAtLeastOurAmt(stream, tls.record_header_len);
        const ct = stream_decoder.decode(tls.ContentType);
        // TODO: Check content type even without eof
        if (ct != content_type) return error.TlsUnexpectedMessage;
        const protocol_version = stream_decoder.decode(u16);
        if (protocol_version != 0x0303) return error.TlsAlertProtocolVersion;
        const record_len = stream_decoder.decode(u16);
        record_decoder.* = stream_decoder.sub(record_len);
    }
    try record_decoder.ensure(4);
    const hst = record_decoder.decode(HandshakeType);
    if (hst != handshake_type) return error.TlsUnexpectedMessage;
    const length = record_decoder.decode(u24);
    // TODO: Handle fragmentation
    const hsd = try record_decoder.sub(length);
    return hsd;
}

// hmac: crypto.auth.hmac.sha2.HmacSha256/384
fn PRF_inner(comptime Hmac: type, secret: []const u8, label: []const u8, seed: []const u8, output: []u8) void {
    var i: u32 = 0;
    const hash_len = Hmac.mac_length;
    var a0: [hash_len]u8 = undefined;
    var a1: [hash_len]u8 = undefined;
    while (true) {
        if (output.len <= i * hash_len) {
            // we do not handle truncation here
            assert(output.len == i * hash_len);
            break;
        }

        // A(i) = hmac(secret, A(i-1))
        // A(0) = _seed
        {
            var ctx = Hmac.init(secret);
            if (i == 0) {
                ctx.update(label);
                ctx.update(seed);
            } else {
                ctx.update(&a0);
            }
            ctx.final(&a1);
        }

        // Output(i) = hmac(secret, A(i) + _seed)
        // where _seed = label + seed for PRF
        {
            var ctx = Hmac.init(secret);
            ctx.update(&a1);
            ctx.update(label);
            ctx.update(seed);
            ctx.final(output[i * hash_len ..][0..hash_len]);
        }
        i += 1;
        @memcpy(&a0, &a1);
    }
}

pub fn PRF(comptime hmac: type, secret: []const u8, label: []const u8, seed: []const u8, comptime output_len: usize) [output_len]u8 {
    const hash_len = hmac.mac_length;
    const extra_len = if (output_len % hash_len == 0) 0 else hash_len - output_len % hash_len;
    const buf_len = output_len + extra_len;
    var buf: [buf_len]u8 = undefined;
    PRF_inner(hmac, secret, label, seed, &buf);
    return buf[0..output_len].*;
}
