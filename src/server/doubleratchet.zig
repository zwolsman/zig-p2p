const std = @import("std");
const Crypto = @import("crypto.zig");
const KeyPair = Crypto.KeyPair;

pub fn init(id: []const u8, sharedKey: [32]u8, keyPair: KeyPair) Session {
    return Session.init(id, sharedKey, keyPair);
}

pub fn initRemoteKey(id: []const u8, sharedKey: [32]u8, remoteKey: [32]u8) !Session {
    return Session.initRemoteKey(id, sharedKey, remoteKey);
}

const Session = struct {
    id: []const u8,
    state: State,

    fn init(id: []const u8, sharedKey: [32]u8, keyPair: KeyPair) Session {
        return Session{ .id = id, .state = State.init(sharedKey, keyPair) };
    }

    fn initRemoteKey(id: []const u8, sharedKey: [32]u8, remoteKey: [32]u8) !Session {
        const keyPair = try Crypto.generateKeypair();
        var session = Session{ .id = id, .state = State.init(sharedKey, keyPair) };

        session.state.DHr = remoteKey;

        const secret = try Crypto.DH(session.state.DHs, session.state.DHr);

        session.state.sendChain = session.state.rootChain.step(secret).chain;

        return session;
    }

    pub fn RatchetEncrypt(self: *Session, plain: []const u8) !Message {
        var header = MessageHeader{
            .DH = self.state.DHs.public_key,
            .N = self.state.sendChain.n,
            .PN = self.state.pn,
        };

        const messageKey = self.state.sendChain.step();

        return Message{ .header = header, .ciphertext = try Crypto.encrypt(messageKey, plain, &header.encode()) };
    }

    pub fn RatchetDecrypt(self: *Session, message: Message) ![]u8 {
        var sc = self.state;
        // TODO: save skipped keys
        // skip keys if they are not equal
        if (!std.mem.eql(u8, message.header.DH[0..], sc.DHr[0..])) {
            sc.skipMessageKeys(sc.DHr, message.header.PN) catch {
                unreachable; // TODO; invalid skipping
            };

            sc.dhRatchet(message.header) catch {
                unreachable; // TODO: can't perform ratchet step
            };
        }
        sc.skipMessageKeys(sc.DHr, message.header.N) catch {
            unreachable; // TODO; invalid skipping
        };
        const mk = sc.receiveChain.step();

        var header = message.header;
        const plaintext = Crypto.decrypt(mk, message.ciphertext, &header.encode());

        sc.keysCount += 1;

        self.state = sc;
        return plaintext;
    }

    fn DeleteMessageKey() void {}
};

const Message = struct { header: MessageHeader, ciphertext: []u8 };
const MessageHeader = struct {
    DH: [32]u8,
    N: u32,
    PN: u32,

    const encodeLen = @sizeOf(u32) + @sizeOf(u32);

    fn encode(self: *MessageHeader) [encodeLen]u8 {
        var buffer: [encodeLen]u8 = undefined;

        @memcpy(buffer[0..@sizeOf(u32)], std.mem.asBytes(&self.N));
        @memcpy(buffer[@sizeOf(u32)..], std.mem.asBytes(&self.PN));

        return buffer;
    }
};

//
// Get returns a message key by the given key and message number.
// Get(k Key, msgNum uint) (mk Key, ok bool, err error)

// Put saves the given mk under the specified key and msgNum.
// Put(sessionID []byte, k Key, msgNum uint, mk Key, keySeqNum uint) error

// DeleteMk ensures there's no message key under the specified key and msgNum.
// DeleteMk(k Key, msgNum uint) error

// DeleteOldMKeys deletes old message keys for a session.
// DeleteOldMks(sessionID []byte, deleteUntilSeqKey uint) error

// TruncateMks truncates the number of keys to maxKeys.
// TruncateMks(sessionID []byte, maxKeys int) error

// Count returns number of message keys stored under the specified key.
// Count(k Key) (uint, error)

// All returns all the keys
// All() (map[string]map[uint]Key, error)

const KeyStorage = struct {
    const Self = @This();
    const entry = struct { messageKey: Crypto.Key, seqNum: u32, sessionID: []const u8 };
    allocator: std.mem.Allocator,
    storage: std.AutoHashMap(Crypto.Key, std.AutoHashMap(u32, entry)),

    fn init(allocator: std.mem.Allocator) Self {
        return Self{ .allocator = allocator, .storage = std.AutoHashMap(Crypto.Key, std.AutoHashMap(u32, entry)).init(allocator) };
    }

    fn get(self: *Self, k: Crypto.Key, msgNum: u32) ?Crypto.Key {
        const msgs = self.storage.get(k) orelse return null;
        const e = msgs.get(msgNum) orelse return null;
        return e.messageKey;
    }
};

const State = struct {
    // DH Ratchet public key (the remote key).
    DHr: [32]u8,

    // DH Ratchet key pair (the self ratchet key).
    DHs: KeyPair,

    // Symmetric ratchet root chain.
    rootChain: RootChain,

    // Symmetric ratchet sending and receiving chains.
    sendChain: Chain,
    receiveChain: Chain,

    // Number of messages in previous sending chain.
    pn: u32,

    // The maximum number of message keys that can be skipped in a single chain.
    // WithMaxSkip should be set high enough to tolerate routine lost or delayed messages,
    // but low enough that a malicious sender can't trigger excessive recipient computation.
    maxSkip: u32,

    // How long we keep messages keys, counted in number of messages received,
    // for example if MaxKeep is 5 we only keep the last 5 messages keys, deleting everything n - 5.
    maxKeep: u32,
    // Max number of message keys per session, older keys will be deleted in FIFO fashion
    maxMessageKeysPerSession: u32,

    // The number of the current ratchet step.
    step: u32,

    // KeysCount the number of keys generated for decrypting
    keysCount: u32,

    fn init(sharedKey: [32]u8, keyPair: KeyPair) State {
        return State{
            .DHs = keyPair,
            .DHr = sharedKey,

            .rootChain = RootChain{ .CK = sharedKey },
            .sendChain = Chain{ .CK = sharedKey, .n = 0 },
            .receiveChain = Chain{ .CK = sharedKey, .n = 0 },

            .pn = 0,
            .maxSkip = 1000,
            .maxKeep = 2000,
            .maxMessageKeysPerSession = 2000,
            .keysCount = 0,
            .step = 0,
        };
    }

    const skippedKey = struct {
        key: [32]u8,
        nr: u32,
        mK: [32]u8,
        seq: u32,
    };

    fn skipMessageKeys(self: *State, key: [32]u8, until: u32) !void {
        _ = key; // autofix
        if (until < self.receiveChain.n) {
            // out of order message
            unreachable;
        }
        if (self.receiveChain.n + self.maxSkip < until) {
            // too many messages
            unreachable;
        }

        while (self.receiveChain.n < until) {
            const mk = self.receiveChain.step();
            std.debug.print("skipped key {any}\n", .{mk});
            self.keysCount += 1;
        }
    }

    fn dhRatchet(self: *State, m: MessageHeader) !void {
        self.pn = self.sendChain.n;
        self.DHr = m.DH;
        // TODO: header keys

        const recvSecret = try Crypto.DH(self.DHs, self.DHr);
        self.receiveChain = self.rootChain.step(recvSecret).chain;

        self.DHs = try Crypto.generateKeypair();

        const sendSecret = try Crypto.DH(self.DHs, self.DHr);
        self.sendChain = self.rootChain.step(sendSecret).chain;
    }
};

const RootChain = struct {
    // Chain Key
    CK: [32]u8,

    // step performs symmetric ratchet step and returns a new chain and new header key.
    fn step(self: *RootChain, key: [32]u8) struct { chain: Chain, nhk: [32]u8 } {
        const keys = Crypto.kdfRk(self.CK, key);

        self.CK = keys.rootKey;
        return .{ .chain = Chain{ .CK = keys.chainKey, .n = 0 }, .nhk = keys.newHeaderKey };
    }
};

const Chain = struct {
    CK: [32]u8,
    n: u32,

    fn step(self: *Chain) [32]u8 {
        const keys = Crypto.KdfCK(&self.CK);
        self.n += 1;
        self.CK = keys.chainKey;
        return keys.messageKey;
    }
};
