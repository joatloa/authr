//! HTTP integration for Actix Web applications.
//!
//! This module exposes the HTTP interface to Authr, including authentication
//! handlers, routing, middleware, and request utilities.
//!
//! The [`router`] module provides the default authentication routes, which
//! can be registered directly in an existing Actix Web application.
//! Individual handlers are also exposed through [`handlers`], allowing
//! applications to define their own routes and customize their HTTP API.
//!
//! The [`middleware`] module provides session-based authentication
//! middleware for protecting application routes, while [`error`] and
//! [`utils`] contain shared HTTP error handling and request utilities.

pub mod cookie;
pub mod error;
pub mod handlers;
pub mod middleware;
pub mod router;
