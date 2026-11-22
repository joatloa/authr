use std::net::SocketAddr;

use url::Url;

use crate::core::error::AuthrError;

#[derive(Debug, Clone)]
/// How Authr determines the public host used in generated URLs and bind address.
pub enum BaseUrl {
    /// Uses a fixed URL for the Authr instance.
    Link { host: String },
    /// Allows Authr to operate across multiple domains.
    List {
        allowed_hosts: Vec<String>,
        fallback: String,
    },
}

impl BaseUrl {
    // -------------------- Helper Methods --------------------

    /// Returns the socket address derived from the configured base URL.
    pub fn socket_addr(&self) -> std::io::Result<SocketAddr> {
        let url = self.fallback_url().map_err(std::io::Error::other)?;

        let host = url
            .host_str()
            .ok_or_else(|| std::io::Error::other("Missing host"))?;

        let port = url
            .port_or_known_default()
            .ok_or_else(|| std::io::Error::other("Missing port"))?;

        let address = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };

        address.parse().map_err(std::io::Error::other)
    }

    /// Resolves the public base URL using the incoming request.
    pub fn resolve(&self, host: Option<&str>, scheme: Option<&str>) -> Result<Url, AuthrError> {
        match self {
            Self::Link { .. } => self.fallback_url(),

            Self::List { .. } => {
                let (Some(host), Some(scheme)) = (host, scheme) else {
                    return self.fallback_url();
                };

                if !matches!(scheme, "http" | "https") || !self.is_host_allowed(host) {
                    return self.fallback_url();
                }

                Url::parse(&format!("{scheme}://{host}")).map_err(|_| AuthrError::Internal)
            }
        }
    }

    /// Checks whether a callback URL belongs to an allowed host.
    pub fn is_allowed(&self, value: &str) -> bool {
        let Ok(url) = Url::parse(value) else {
            return false;
        };

        if !matches!(url.scheme(), "http" | "https") {
            return false;
        }

        let Some(host) = url.host_str() else {
            return false;
        };

        self.is_host_allowed(host)
    }

    // -------------------- Internal Helpers --------------------

    /// Returns the fallback URL.
    fn fallback_url(&self) -> Result<Url, AuthrError> {
        match self {
            Self::Link { host } => Url::parse(host),
            Self::List { fallback, .. } => Url::parse(fallback),
        }
        .map_err(|_| AuthrError::Internal)
    }

    /// Checks whether a hostname matches one of the configured hosts.
    fn is_host_allowed(&self, host: &str) -> bool {
        match self {
            Self::Link { host: base } => Self::host_matches_url(host, base),

            Self::List {
                allowed_hosts,
                fallback,
            } => {
                allowed_hosts
                    .iter()
                    .any(|allowed| Self::hosts_match(host, allowed))
                    || Self::host_matches_url(host, fallback)
            }
        }
    }

    /// Compares a hostname against the hostname of a URL.
    fn host_matches_url(host: &str, value: &str) -> bool {
        Url::parse(value)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .is_some_and(|url_host| host.eq_ignore_ascii_case(&url_host))
    }

    /// Compares two host values, ignoring their ports.
    fn hosts_match(first: &str, second: &str) -> bool {
        let first = Self::parse_host(first);
        let second = Self::parse_host(second);

        first
            .zip(second)
            .is_some_and(|(first, second)| first.eq_ignore_ascii_case(&second))
    }

    /// Extracts the hostname from a host value.
    fn parse_host(value: &str) -> Option<String> {
        Url::parse(&format!("http://{value}"))
            .ok()?
            .host_str()
            .map(str::to_owned)
    }
}

// -------------------- Conversions --------------------

impl From<String> for BaseUrl {
    fn from(host: String) -> Self {
        Self::Link { host }
    }
}

impl From<&str> for BaseUrl {
    fn from(host: &str) -> Self {
        Self::Link {
            host: host.to_string(),
        }
    }
}
