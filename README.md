# Zig P2P

> A peer-to-peer networking implementation in Zig. This project is for learning purposes and is not production-ready.

## Overview

Zig P2P is an experimental peer-to-peer networking protocol written in Zig. It explores concepts such as cryptographic identity, message routing, and end-to-end encryption. The project is intended as a learning experience and is not yet suitable for production use.

## Features

- **Peer Identity**: Nodes are identified using Ed25519 public keys.
- **Routing**: Messages can be relayed through intermediary nodes.
- **Encryption**: End-to-end encryption is established using X25519 key derivation.
- **Frames & Packets**: Structured messaging with encryption metadata and authentication.

## Specification

The protocol specification is documented in [`SPEC.md`](SPEC.md), detailing the message structures, encryption schemes, and overall architecture of the network.

## Installation

Ensure you have Zig installed on your system. You can install Zig from [ziglang.org](https://ziglang.org/) or use [Zig Version Manager](http://zvm.app).

```sh
# Clone the repository
git clone https://github.com/zwolsman/zig-p2p.git
cd zig-p2p

# Build the project
zig build
```

## Usage

Since this project is a learning experiment, there is no stable API. However, you can run a test to verify the basic networking functionality of the nodes.

### Example: Running Two Connected Nodes

In this example, we'll run two nodes that connect to each other. One node will listen on port `1111` and another on port `2222`. The node on port `2222` will bootstrap from the first node.

1. **Start the first node (listening on port 1111):**

   ```sh
   zig build node -- -l 1111
   ```

   This command starts the first node, and it listens on port `1111`. This node doesn't need to connect to any other node initially.

2. **Start the second node (listening on port 2222) and connect it to the first node:**

   ```sh
   zig build node -- -i -l 2222 127.0.0.1:1111
   ```

   This command starts the second node, which listens on port `2222`. The `-i` flag opens an interactive TTY for the second node. The trailing address `127.0.0.1:1111` is used to bootstrap the second node, instructing it to connect to the first node running on port `1111`.

Once both nodes are running, they should be connected, and you can test the network communication between them.

## Interactive TTY Commands

When you start a node with the `-i` flag, an interactive TTY (terminal) session is opened. This allows you to interact with the node in real-time. Below are some specific commands you can use within the interactive TTY:

### Viewing Connected Peers

To view the list of connected peers for the current node, run:

```sh
peers
```

This will display the peers that the node is currently connected to. For example, Node 2 should show Node 1 as a peer if the bootstrap process was successful.

### Broadcasting a Message to All Nodes

To broadcast a message to all nodes in the network, use the broadcast command. The message will be sent to all connected nodes.

```sh
broadcast <msg>
```

Replace `<msg>` with the message you want to send. For example:

```sh
broadcast Hello, network!
```

### Routing a Message to a Specific Node

You can send a message directly to a specific node by routing it using the node's public key. This will send the message to the intended destination, and the message will be echoed back from the destination node.

```sh
route <dst public key> <msg>
```

- Replace `<dst public key>` with the public key of the destination node.
- Replace `<msg>` with the message you want to send.

**Example:**

```sh
route <public_key_of_node_1> Hello Node 1!
```

This will send the message `Hello Node 1!` directly to Node 1. Node 1 should echo the message back.

#### Notes

- The peers command helps you confirm the node's network state and whether it is successfully connected to other nodes.
- The broadcast command is useful for sending messages to the entire network.
- The route command allows you to send a message to a specific node, making it possible to target specific destinations in the network.

Feel free to experiment with these commands to test your network's behavior and ensure that your nodes are communicating as expected!

### Stopping the Nodes

To stop the nodes, simply interrupt the process in the terminal (usually by pressing `Ctrl+C`).
