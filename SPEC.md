# Protocol Specification v1.0.0

> This document describes the frame structure and message exchange protocol for the custom peer-to-peer network.

## Table of Contents

- [Overview](#overview)
- [Packet structure](#packet-structure)
  - [Packet Header](#packet-header)
  - [Packet Flags](#packet-flags)
  - [Encryption metadata](#encryption-metadata)
- [ID structure](#id-structure)
- [Frame Structures](#frame-structures)
  - [HelloFrame](#helloframe)
  - [FindNodeFrame](#findnodeframe)
  - [RouteFrame](#routeframe)
  - [EchoFrame](#echoframe)
  - [BroadcastFrame](#broadcastframe)
- [Message Signing](#message-signing)
- [End-to-End encryption](#end-to-end-encryption)

## Overview

This protocol defines a set of message frames used for communication between nodes in the network. Messages are structured binary frames that adhere to specific formats, ensuring efficient and secure data exchange.

## Packet Structure

Each frame is encapsulated within a `Packet`, which includes metadata about the operation and type of message being sent.

### Packet Header

| Field   | Type  | Size | Description                                    |
| ------- | ----- | ---- | ---------------------------------------------- |
| `len`   | `u32` | 4    | Length of the packet payload                   |
| `flags` | `u8`  | 1    | Packet flags indicating encryption and signing |

### Packet Flags

The `flags` field in the `PacketHeader` indicates whether the packet is:

- **Signed (0x1):** The packet is signed with the sender’s private key to ensure authenticity.
- **Encrypted (0x2):** The packet is encrypted using the double-ratchet encryption method.

### Encryption Metadata

If the packet is end-to-end encrypted, an `EncryptionMetadata` section is included:

| Field | Type     | Size | Description                                           |
| ----- | -------- | ---- | ----------------------------------------------------- |
| `dh`  | `[32]u8` | 32   | Diffie-Hellman public key for key agreement           |
| `n`   | `u32`    | 4    | Message number in the encryption sequence             |
| `pn`  | `u32`    | 4    | Previous message number to prevent reordering attacks |

## ID Structure

The `ID` structure uniquely identifies a node in the network.

### Structure

| Field        | Type          | Size | Description                    |
| ------------ | ------------- | ---- | ------------------------------ |
| `public_key` | `[32]u8`      | 32   | Ed25519 public key of the node |
| `address`    | `net.Address` | Var  | IPv4 or IPv6 network address   |

The `address` field can contain either an IPv4 or IPv6 address. The format is as follows:

- **IPv4:** 4-byte address + 2-byte port
- **IPv6:** 16-byte address + 4-byte scope ID + 4-byte flow info + 2-byte port

This structure allows nodes to be identified both cryptographically (via their Ed25519 public key) and by their network location (IPv4/IPv6 address and port).

## Frame Structures

### HelloFrame

The `HelloFrame` is used to initiate communication between peers.

#### Structure

| Field        | Type     | Size | Description                     |
| ------------ | -------- | ---- | ------------------------------- |
| `peer_id`    | `ID`     | Var  | Unique identifier of the peer   |
| `public_key` | `[32]u8` | 32   | X25519 public key of the peer   |
| `nonce`      | `[16]u8` | 16   | Random nonce for authentication |

### FindNodeFrame

The `FindNodeFrame` is used for peer discovery.

#### Request Structure

| Field        | Type     | Size | Description                       |
| ------------ | -------- | ---- | --------------------------------- |
| `public_key` | `[32]u8` | 32   | Public key of the requesting peer |

#### Response Structure

| Field      | Type   | Size | Description              |
| ---------- | ------ | ---- | ------------------------ |
| `len`      | `u8`   | 1    | Number of peer IDs found |
| `peer_ids` | `[]ID` | Var  | List of peer IDs found   |

### RouteFrame

The `RouteFrame` is used for routing messages through multiple hops.

#### Structure

| Field     | Type     | Size | Description                           |
| --------- | -------- | ---- | ------------------------------------- |
| `src`     | `[32]u8` | 32   | Source node ID                        |
| `dst`     | `[32]u8` | 32   | Destination node ID                   |
| `hops`    | `[]ID`   | Var  | List of intermediary hops             |
| `payload` | `Frame`  | Var  | Any other frame, encrypted end-to-end |

#### End-to-End encryption

The `payload` within the `RouteFrame` is encrypted using an X25519-derived key. The sender derives an ephemeral X25519 key from the Ed25519 public key of the `dst` (destination node). This ensures that only the intended recipient can decrypt and process the encapsulated frame, maintaining confidentiality and integrity during transit.

### EchoFrame

The `EchoFrame` is used for debugging and simple message exchange.

#### Structure

| Field | Type   | Size | Description          |
| ----- | ------ | ---- | -------------------- |
| `txt` | `[]u8` | Var  | Text message content |

### BroadcastFrame

The `BroadcastFrame` is used for propagating messages to multiple peers.

#### Structure

| Field   | Type     | Size | Description                                       |
| ------- | -------- | ---- | ------------------------------------------------- |
| `src`   | `[32]u8` | 32   | Source node ID                                    |
| `nonce` | `[16]u8` | 16   | Unique identifier to prevent duplicate processing |
| `ts`    | `i128`   | 16   | Timestamp in nanoseconds                          |
| `n`     | `u8`     | 1    | Number of hops allowed                            |

## Message Signing

Each packet is signed by the public key of the sending node. This ensures that messages are verifiable and originate from a trusted source, preventing tampering or impersonation attacks.

## End-to-End Encryption

After the exchange of `HelloFrame` messages, end-to-end encryption is established between peers. The encryption method used is AES-256 in CTR mode, with messages signed using HMAC-SHA256. This guarantees both confidentiality and integrity of the communication.

## Message Exchange

Each frame follows a strict encoding and decoding process. The sender must correctly format the frame, while the receiver must validate and parse it according to its structure.

This protocol ensures secure and efficient communication between nodes, supporting essential functionalities such as peer discovery, routing, and broadcasting.
