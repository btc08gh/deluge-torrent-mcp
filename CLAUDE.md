# CLAUDE.md

## Project Overview

An MCP server written in Rust that bridges AI assistants to a running Deluge torrent daemon (`deluged`). Built with the [Model Context Protocol Rust SDK](https://github.com/modelcontextprotocol/rust-sdk), it exposes 13 tools covering torrent management (add, remove, list, pause, resume, status), file operations (move storage, rename folders/files, force recheck), and server queries (free space, path size).

Supports both **stdio** (Claude Desktop) and **HTTP/SSE** (remote/agentic) transports. Includes tiered safety gates to guard against LLM hallucination, and configurable TLS certificate handling for Deluge's default self-signed certificates.

## Tech Stack
Rust for the code
Cargo for package management and build system

## Dependencies

| Crate | Purpose |
|---|---|
| `rmcp` | Official MCP Rust SDK — stdio and HTTP/SSE transports |
| `tokio` | Async runtime |
| `native-tls` | TLS for Deluge RPC connection — tolerates Deluge's legacy v1 self-signed certificates that rustls rejects |
| `tokio-native-tls` | Async wrapper for native-tls |
| `bytes` | Byte buffer handling for binary protocol framing |
| `flate2` | zlib compression/decompression for Deluge RPC message bodies |
| `serde` | Serialization framework |
| `base64` | Encode .torrent file content for `add_torrent_file` |
| `sha2` | SHA-256 hashing for TLS certificate fingerprint computation |
| `anyhow` | Flexible error handling |
| `thiserror` | Structured error types |
| `axum` | HTTP server for the HTTP/SSE transport |
| `tower-http` | CORS and tracing middleware layers for axum |
| `tracing` | Logging |
| `tracing-subscriber` | Log output formatting — **must be configured to write to stderr or a file, never stdout**. Any output on stdout corrupts the JSON-RPC framing used by the MCP stdio transport. |
| `clap` | CLI args (Deluge host/port/credentials, transport selection, `--enable-tool`, `--disable-tool`, `--list-tools`, `--api-token`, `--http-bind`, `--test-connection`) — credentials can also be supplied via environment variables (`DELUGE_HOST`, `DELUGE_PORT`, `DELUGE_USERNAME`, `DELUGE_PASSWORD`, `DELUGE_API_TOKEN`) |

rencode serialization is implemented internally as `src/rencode.rs` rather than using a third-party crate.

## Architecture

This is an MCP server that bridges AI models (e.g. Claude) to a running Deluge daemon (`deluged`).

```
MCP Client (Claude Desktop, agentic frameworks, etc.) <--MCP--> deluge-torrent-mcp <--Deluge RPC--> deluged
```

The server supports two MCP transports:
- **stdio** — for local use with Claude Desktop and similar clients
- **HTTP/SSE** — for remote use with network-accessible clients; MCP clients connect to `http://<host>:<port>/mcp`. Protected by optional Bearer token authentication (`--api-token`).

### Deluge RPC API
Deluge exposes a custom binary RPC protocol over TCP (default port 58846). The daemon must be running and accessible. Authentication is required before issuing commands. The API is documented at https://deluge.readthedocs.io/en/deluge-2.0.1/reference/api.html

## MCP Tools

| Tool | Deluge RPC Method | Description |
|---|---|---|
| `add_torrent` | `core.add_torrent_magnet` / `core.add_torrent_url` / `core.add_torrent_file` | Add a torrent by magnet link, .torrent URL, or .torrent file (via server file path or base64-encoded content) |
| `remove_torrent` | `core.remove_torrent` | Remove a torrent, optionally deleting data |
| `list_torrents` | `core.get_torrents_status` | List all torrents with status fields |
| `get_torrent_status` | `core.get_torrent_status` | Get detailed status for a single torrent |
| `pause_torrent` | `core.pause_torrent` | Pause a torrent |
| `resume_torrent` | `core.resume_torrent` | Resume a paused torrent |
| `set_torrent_options` | `core.set_torrent_options` | Set per-torrent options (e.g. download path, ratio limits) |
| `move_storage` | `core.move_storage` | Move a torrent's storage to a new path |
| `rename_folder` | `core.rename_folder` | Rename a folder within a torrent |
| `rename_files` | `core.rename_files` | Rename one or more files within a torrent |
| `force_recheck` | `core.force_recheck` | Force a hash recheck of a torrent's files |
| `get_free_space` | `core.get_free_space` | Get free disk space for a given path |
| `get_path_size` | `core.get_path_size` | Get the size of a path on the server |

Torrents are identified by their **info hash** (40-character hex string).

### Safety Gates

Tools have two default states. Five tools are **disabled by default** to guard against LLM hallucination:

| Tool | Default | Reason |
|---|---|---|
| `add_torrent`, `list_torrents`, `get_torrent_status`, `pause_torrent`, `resume_torrent`, `set_torrent_options`, `get_free_space`, `get_path_size` | enabled | Safe read/write operations |
| `move_storage`, `rename_folder`, `rename_files`, `force_recheck` | disabled | Modifies filesystem paths or interrupts downloads |
| `remove_torrent` | disabled | Can permanently delete downloaded data |

Tools are enabled or disabled via `--enable-tool <PATTERN>` / `--disable-tool <PATTERN>`. Patterns are matched as case-sensitive substrings of tool names (minimum 3 characters). Both singular (`--enable-tool`) and plural (`--enable-tools`) forms are accepted. Flags are processed in CLI order — later flags override earlier ones.

`--list-tools` prints all tools with their default state and exits without requiring credentials.

When a disabled tool is called, the server returns an error to the LLM with the exact `--enable-tool` flag needed to enable it.

### Wire Format

```
[version: 1 byte][length: 4 bytes big-endian][body: N bytes]
```

- **Body**: rencode-serialized, zlib-compressed
- **Request packet**: `(request_id, method, args, kwargs)`
- **Response types**:
  - `(1, request_id, result)` — RPC_RESPONSE
  - `(2, request_id, exception_type, exception_args, exception_kwargs, traceback)` — RPC_ERROR
  - `(3, event_name, event_args)` — RPC_EVENT (server-initiated)

### Connection & Auth

1. Connect via TLS TCP to `host:port` (default `localhost:58846`)
2. Call `daemon.login(username, password, client_version=...)` — returns auth level (0–10)
3. All subsequent calls are dispatched with the established session

### TLS Certificate Handling

Deluge daemons use self-signed certificates by default. Certificate verification is configurable:

- **Default (skip verification)**: Accepts any certificate. On each connection, logs the certificate's SHA-256 fingerprint at `WARN` level along with the `--cert-fingerprint` flag to use for pinning, making it easy to copy-paste for future use.
- **Pinned fingerprint** (`--cert-fingerprint <SHA256>`): Accepts only a certificate matching the given fingerprint. All others are rejected.

Implemented via `native-tls` with `danger_accept_invalid_certs(true)`. After the TLS handshake, the peer certificate is extracted via `peer_certificate()`, its DER bytes are hashed with SHA-256, and the fingerprint is either verified against the pinned value or logged as a WARN with the copy-pasteable `--cert-fingerprint` flag.

## File Structure

| Path | Purpose |
|---|---|
| `Cargo.toml` | The manifest file that defines dependencies, metadata, and crate type. |
| `Cargo.lock` | Contains the exact dependency versions used in the last build. |
| `src/` | Contains all the source code for the project. |
| `src/main.rs` | Entry point — CLI arg parsing, transport selection, server startup, HTTP auth middleware. |
| `src/rencode.rs` | Internal rencode serializer/deserializer (Deluge wire format). |
| `src/deluge/mod.rs` | Deluge RPC client — TLS connection, cert fingerprint logging/pinning, auth, request multiplexing, zlib framing. |
| `src/tools/mod.rs` | MCP tool implementations — all 13 tools, safety gate helpers, Value→JSON conversion. |
| `tests/` | Integration tests. |

## Commands

```bash
# Build the project
cargo build
# Run the project
cargo run
# Run tests
cargo test
# Build documentation
cargo doc --open
```
