use std::borrow::Cow;

use sha1::{Digest, Sha1};

use crate::common;
use crate::MojangError;

/// Info on all Mojang Blocked Servers
/// ## Example
/// ```rust
/// // Import Lib
/// use mojang::BlockedServers;
///
/// // Fetch blocked servers
/// let blocked = BlockedServers::new().unwrap();
///
/// // Check if server is blocked
/// assert!(blocked.is_blocked("mc.playmc.mx"));
/// ```
#[derive(Debug, Clone)]
pub struct BlockedServers {
    /// Hashes of all Blocked Servers
    pub hashes: Vec<String>,
}

impl BlockedServers {
    /// Fetch current Blocked Servers List
    /// ## Example
    /// ```rust
    /// # use mojang::BlockedServers;
    /// let blocked = BlockedServers::new().unwrap();
    /// ```
    pub fn new() -> Result<BlockedServers, MojangError> {
        let agent = common::ureq_agent();
        let resp = match agent
            .get("https://sessionserver.mojang.com/blockedservers")
            .call()
        {
            Ok(i) => i.into_string().unwrap(),
            Err(e) => return Err(MojangError::RequestError(e)),
        };

        Ok(BlockedServers {
            hashes: resp.lines().map(|x| x.to_string()).collect(),
        })
    }

    /// Check if the supplied address is in the blocklist, and if it is then return the matching pattern.
    /// ## Example
    /// ```rust
    /// # use mojang::BlockedServers;
    /// use std::borrow::Cow;
    ///
    /// // Use our own blocked servers list for demonstration purposes.
    /// let blocked = BlockedServers {
    ///     hashes: vec![
    ///         // *.example.com
    ///         String::from("8c7122d652cb7be22d1986f1f30b07fd5108d9c0"),
    ///         // 192.0.*
    ///         String::from("8c15fb642b3e8f58480df51798382f1016e748eb"),
    ///         // 127.0.0.1
    ///         String::from("4b84b15bff6ee5796152495a230e45e3d7e947d9"),
    ///     ],
    /// };
    ///
    /// // Find the matching pattern
    /// assert_eq!(blocked.find_blocked_pattern("mc.example.com"), Some(Cow::from("*.example.com")));
    /// assert_eq!(blocked.find_blocked_pattern("192.0.2.235"), Some(Cow::from("192.0.*")));
    /// assert_eq!(blocked.find_blocked_pattern("127.0.0.1"), Some(Cow::from("127.0.0.1")));
    /// assert_eq!(blocked.find_blocked_pattern("127.0.0.2"), None);
    /// ```
    pub fn find_blocked_pattern<'a>(&self, address: &'a str) -> Option<Cow<'a, str>> {
        let address_parts: Vec<&str> = address.split('.').collect();

        if self.is_pattern_blocked(&address) {
            return Some(Cow::Borrowed(address));
        }

        if is_ipv4(&address_parts) {
            (1..address_parts.len())
                .rev()
                .map(|i| format!("{}.*", address_parts[..i].join(".")))
                .find(|pattern| self.is_pattern_blocked(&pattern))
                .map(Cow::Owned)
        } else {
            (1..address_parts.len())
                .map(|i| format!("*.{}", address_parts[i..].join(".")))
                .find(|pattern| self.is_pattern_blocked(&pattern))
                .map(Cow::Owned)
        }
    }

    /// Check if the supplied address is in the blocklist
    /// ## Example
    /// ```rust
    /// # use mojang::BlockedServers;
    /// // Fetch Blocked Servers
    /// let blocked = BlockedServers::new().unwrap();
    ///
    /// // Check if server is blocked
    /// assert!(blocked.is_blocked("mc.playmc.mx"));
    /// ```
    pub fn is_blocked(&self, address: &str) -> bool {
        self.find_blocked_pattern(address).is_some()
    }

    fn is_pattern_blocked(&self, pattern: &str) -> bool {
        let hash = format!("{:#02X}", Sha1::digest(pattern.as_bytes())).to_lowercase();
        self.hashes.contains(&hash)
    }
}

#[doc(hidden)]
/// Tests if an address is ipv4 naively to better match how mojang determines if an address is ipv4 or not.
/// ## Example
/// ```rust
/// # use mojang::server_block::is_ipv4;
/// assert!(!is_ipv4(&["mc", "example", "com"]));
/// assert!(is_ipv4(&["192", "0", "2", "235"]));
/// ```
pub fn is_ipv4(ip: &[&str]) -> bool {
    // If thare are too many sections, and each octet is a valid u8
    ip.len() == 4 && ip.iter().all(|x| x.parse::<u8>().is_ok())
}