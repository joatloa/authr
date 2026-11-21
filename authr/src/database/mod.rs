//! Database abstractions and persistence implementations.
//!
//! This module defines the storage contract used by Authr and provides
//! the models, schema, and migrations required to persist authentication
//! data.
//!
//! The [`store`] module exposes the [`AuthDatabase`] trait and its
//! associated query interfaces, allowing different database backends
//! to implement Authr's persistence layer.
//!
//! The [`adapter`] module contains the built-in Diesel adapter, while
//! [`models`], [`schema`], and [`migrations`] provide the database
//! structures and migration utilities.

pub mod adapter;
pub mod migrations;
pub mod models;
pub mod schema;
pub mod store;
