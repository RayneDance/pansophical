//! Stdio transport: async line-delimited JSON-RPC reader/writer.
//!
//! The server's stdout is the JSON-RPC channel. Child processes
//! must NEVER inherit this fd.
