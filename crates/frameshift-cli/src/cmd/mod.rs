//! CLI subcommand implementations.
//!
//! Each module in this directory owns one top-level subcommand group. The
//! `Subcommand` enum in `main.rs` dispatches to the appropriate module.

pub mod automate;
pub mod diff;
pub mod feedback;
pub mod grow;
pub mod migrate;
pub mod prefs;
pub mod publish;
pub mod register;
pub mod render;
pub mod rule;
pub mod search;
pub mod select;
pub mod skill;
pub mod use_persona;
pub mod verify;
