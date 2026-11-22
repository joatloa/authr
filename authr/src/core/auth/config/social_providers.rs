use std::collections::HashMap;

use crate::core::oauth::Provider;

#[derive(Debug, Clone)]
/// OAuth providers available for social sign-in, keyed by provider ID.
pub struct SocialProviders(HashMap<String, Provider>);

impl SocialProviders {
    pub fn new(providers: Vec<(String, Provider)>) -> SocialProviders {
        Self(providers.into_iter().collect())
    }
    pub fn get(&self, id: &str) -> Option<&Provider> {
        self.0.get(id)
    }
}
