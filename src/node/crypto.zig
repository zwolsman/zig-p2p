const std = @import("std");
const crypto = std.crypto;
pub const KeyPair = crypto.dh.X25519.KeyPair;
pub const Key = [32]u8;

const allocator = std.heap.page_allocator;
const errors = error{SignatureMismatch};

pub fn generateKeypair() !KeyPair {
    return crypto.dh.X25519.KeyPair.create(null);
}

pub fn kdfRk(rootKey: [32]u8, dhOut: [32]u8) struct {
    rootKey: [32]u8,
    chainKey: [32]u8,
    newHeaderKey: [32]u8,
} {
    const prk = crypto.kdf.hkdf.HkdfSha256.extract(&rootKey, &dhOut);
    var out: [96]u8 = undefined;
    crypto.kdf.hkdf.HkdfSha256.expand(&out, "rsZUpEuXUqqwXBvSy3EcievAh4cMj6QL", prk);

    return .{
        .rootKey = out[0..32].*,
        .chainKey = out[32..64].*,
        .newHeaderKey = out[64..].*,
    };
}

pub fn deriveEncKeys(mk: [32]u8) struct { encKey: [32]u8, authKey: [32]u8, iv: [16]u8 } {
    const prk = crypto.kdf.hkdf.HkdfSha256.extract(&mk, &mk);
    var out: [80]u8 = undefined;
    crypto.kdf.hkdf.HkdfSha256.expand(&out, "pcwSByyx2CRdryCffXJwy7xgVZWtW5Sh", prk);
    return .{
        .encKey = out[0..32].*,
        .authKey = out[32..64].*,
        .iv = out[64..].*,
    };
}

pub fn encrypt(mk: [32]u8, in: []const u8, ad: []const u8) ![]u8 {
    const keys = deriveEncKeys(mk);

    const out = try allocator.alloc(u8, in.len + keys.iv.len + 32);

    @memcpy(out[0..16], &keys.iv);

    const ctx = crypto.core.aes.Aes256.initEnc(keys.encKey);
    crypto.core.modes.ctr(crypto.core.aes.AesEncryptCtx(crypto.core.aes.Aes256), ctx, out[16 .. 16 + in.len], in, keys.iv, std.builtin.Endian.big);

    const sig = computeSignature(keys.authKey, out[0 .. out.len - 32], ad);

    @memcpy(out[out.len - 32 ..], &sig);
    return out;
}

fn computeSignature(key: Key, cipherText: []const u8, associatedData: []const u8) [crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 {
    var out: [32]u8 = undefined;
    var h = crypto.auth.hmac.sha2.HmacSha256.init(&key);
    h.update(associatedData);
    h.update(cipherText);

    h.final(&out);
    return out;
}

pub fn decrypt(mk: [32]u8, in: []const u8, ad: []const u8) ![]u8 {
    const keys = deriveEncKeys(mk);
    const signature = in[in.len - 32 ..];

    const ciphertext = in[16 .. in.len - 32];
    const iv = in[0..16].*;

    const s = computeSignature(keys.authKey, in[0 .. in.len - 32], ad);
    if (!std.mem.eql(u8, signature, &s)) {
        return errors.SignatureMismatch;
    }

    const out = try allocator.alloc(u8, ciphertext.len);

    const ctx = crypto.core.aes.Aes256.initEnc(keys.encKey);
    crypto.core.modes.ctr(crypto.core.aes.AesEncryptCtx(crypto.core.aes.Aes256), ctx, out, ciphertext, iv, std.builtin.Endian.big);
    return out;
}

pub fn KdfCK(ck: []u8) struct { chainKey: [32]u8, messageKey: [32]u8 } {
    var h = crypto.auth.hmac.sha2.HmacSha256.init(ck);

    var chainKey: [32]u8 = undefined;
    h.update(&[_]u8{15});

    h.final(&chainKey);

    var messageKey: [32]u8 = undefined;
    h.update(&[_]u8{16});
    h.final(&messageKey);
    return .{ .chainKey = chainKey, .messageKey = messageKey };
}

pub fn DH(kp: KeyPair, public_key: [32]u8) ![32]u8 {
    return try crypto.dh.X25519.scalarmult(kp.secret_key, public_key);
}
