# authr

**A flexible authentication library for Rust applications.**

`authr` is an authentication library built with Rust, Actix Web, and Diesel. It provides email-and-password authentication, OAuth 2.0 integrations, session management, and database persistence.

The goal is to provide a flexible authentication foundation that can be integrated into Rust applications without having to implement authentication infrastructure from scratch.

## Features

- **Email and password authentication** — sign-up and sign-in with Argon2 password hashing.
- **OAuth 2.0** — authentication through external OAuth providers.
- **Session management** — create, validate, update, and revoke user sessions.
- **Database persistence** — Diesel-powered storage with connection pooling.
- **Multiple database backends** — MySQL, PostgreSQL, and SQLite.
- **Actix Web integration** — HTTP routes and session middleware.
- **Secure token handling** — cryptographic hashing and secret derivation.

## Installation

Add `authr` to your `Cargo.toml`:

```
[dependencies]
authr = "0.1"
```

By default, the MySQL backend is enabled.

### Database backends

You can choose a different database backend using Cargo features.

| Backend    | Feature           |
| ---------- | ----------------- |
| MySQL      | `mysql` (default) |
| PostgreSQL | `postgres`        |
| SQLite     | `sqlite`          |

To use PostgreSQL:

```
[dependencies]
authr = { version = "0.1", default-features = false, features = ["postgres"] }
```

To use SQLite:

```
[dependencies]
authr = { version = "0.1", default-features = false, features = ["sqlite"] }
```

Select one database backend at a time.

## Configuration

`authr` provides an `AuthrConfig` configuration structure for controlling authentication behavior.

Configuration includes:

- Application name
- Base URL and authentication route prefix
- Database connection URL
- Application secret
- Email-and-password authentication settings
- Social authentication providers
- Logging configuration

The default authentication route prefix is `/api/auth`.

## Authentication

### Email and password

`authr` supports account registration and email-based sign-in.

Passwords are hashed using Argon2 rather than being stored in plaintext. Authentication operations also support session creation and management.

### OAuth 2.0

External authentication providers can be configured through the social provider configuration.

OAuth authentication handles the authorization flow, authorization-code exchange, access-token refresh, and retrieval of provider user information.

The library currently includes Google as an OAuth provider.

## Database

Database operations are handled through Diesel.

Supported backends:

- MySQL
- PostgreSQL
- SQLite

The library provides persistence for:

- Users
- Accounts
- Sessions
- Verifications

Database migrations are included in the crate and are initialized by the database adapter.

## Documentation

API documentation is available on [docs.rs](https://docs.rs/authr).

For installation and source code, visit the [GitHub repository](https://github.com/joatloa/authr).

## License

This project is licensed under the MIT License.
