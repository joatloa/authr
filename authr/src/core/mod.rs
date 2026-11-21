//! Core authentication functionality and shared abstractions.
//!
//! This module contains the configuration, context, types, and utilities
//! used throughout Authr. It also provides OAuth provider abstractions
//! and built-in provider implementations.
//!
//! The [`auth`] module exposes authentication configuration and context,
//! while [`oauth`] provides the interfaces and types required to integrate
//! external OAuth providers.
//!
//! Cryptographic operations, secret management, and shared authentication
//! utilities are also defined here.

pub mod auth;
pub mod error;
pub mod oauth;
pub mod secrets;
pub mod types;
pub mod utils;
