// lib.rs

pub use prost::Message;
pub use tracing::*;

pub use config::*;

mod config;

// This module contains structs and enums that are generated from the protocol buffer (protobuf)
// definitions of the `meshtastic/protobufs` Git submodule. These structs and enums
// are not edited directly, but are instead generated at build time.

pub mod protobufs {
    #![allow(missing_docs)]
    #![allow(non_snake_case)]
    #![allow(unknown_lints)]
    #![allow(clippy::empty_docs)]
    #![allow(clippy::doc_lazy_continuation)]
    #![allow(clippy::doc_overindented_list_items)]
    include!("generated/meshtastic.rs");
}

// EOF
