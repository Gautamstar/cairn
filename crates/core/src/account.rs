//! Accounts, sites, and sessions: who may read which site's statistics.
//!
//! Everything here is a pure function over its inputs, like the rest of this
//! crate. Randomness and the clock are passed in by the caller, so a session
//! token and a password hash are both reproducible in a unit test.
//!
//! ## Why this exists
//!
//! Cairn began as one person's analytics for their own three sites, where
//! `GET /api/stats/{site}` returning data to anyone was a deliberate choice.
//! The moment a second person's site is on the same table that choice becomes
//! someone else's data leak, so sites are now owned, private by default, and
//! public only when their owner says so.
//!
//! ## Item shapes
//!
//! These share the events table and sit in their own key space, so nothing
//! here can collide with an `E#` event or an `A#` aggregate:
//!
//! ```text
//! U#{email}       PROFILE       password hash, plan, created
//! U#{email}       SITE#{site}   membership, for listing a user's sites
//! S#{site}        META          owner, visibility, created
//! T#{token_hash}  SESSION       email, expiry (DynamoDB TTL reaps it)
//! ```

use std::fmt;

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;

/// Upper bound on a site identifier. Shorter than [`crate::event::MAX_SITE_LEN`]
/// because a registered site is typed by a human, not accepted from a payload.
pub const MAX_SITE_ID_LEN: usize = 63;
/// Passwords below this are refused at signup.
pub const MIN_PASSWORD_LEN: usize = 10;
/// Bound on what will be hashed. Argon2 is deliberately slow, so an unbounded
/// password is a free way to burn Lambda duration.
pub const MAX_PASSWORD_LEN: usize = 256;
pub const MAX_EMAIL_LEN: usize = 254;
/// How long a session lasts before the TTL reaps its row.
pub const SESSION_DAYS: i64 = 30;

/// Key of the single row listing every registered site.
///
/// The rollup needs to know which sites exist, and finding `S#` rows in a table
/// dominated by events would mean a scan. One string set, updated atomically as
/// sites come and go, is a single cheap read instead.
pub const REGISTRY_PK: &str = "REGISTRY";
pub const REGISTRY_SK: &str = "SITES";

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum AccountError {
    #[error("email is not a valid address")]
    EmailInvalid,
    #[error("password must be at least {MIN_PASSWORD_LEN} characters")]
    PasswordTooShort,
    #[error("password is too long")]
    PasswordTooLong,
    #[error("site id must be 1-{MAX_SITE_ID_LEN} characters of a-z, 0-9, dot or hyphen")]
    SiteIdInvalid,
    #[error("password hashing failed")]
    HashFailed,
}

/// A normalised email address: trimmed and lowercased, so `A@B.com` and
/// `a@b.com ` are one account rather than two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Email(String);

impl Email {
    pub fn parse(raw: &str) -> Result<Self, AccountError> {
        let email = raw.trim().to_ascii_lowercase();
        if email.len() > MAX_EMAIL_LEN || email.is_empty() {
            return Err(AccountError::EmailInvalid);
        }
        // Deliberately not RFC 5322. The only thing that matters here is that
        // it looks like an address and cannot smuggle a key delimiter into a
        // partition key; deliverability is proven by mail arriving, not by a
        // regex.
        let mut parts = email.split('@');
        let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(AccountError::EmailInvalid);
        };
        if local.is_empty() || domain.is_empty() || !domain.contains('.') {
            return Err(AccountError::EmailInvalid);
        }
        if email.contains('#') || email.chars().any(char::is_whitespace) {
            return Err(AccountError::EmailInvalid);
        }
        Ok(Self(email))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Partition key for this account's rows.
    pub fn pk(&self) -> String {
        format!("U#{}", self.0)
    }
}

impl fmt::Display for Email {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A site identifier, as typed into `data-site` on the tracker script.
///
/// The character set is restricted rather than merely length-checked, because
/// a registered site id is a component of a partition key. Allowing `#` would
/// let one site's key be spelled two ways.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteId(String);

impl SiteId {
    pub fn parse(raw: &str) -> Result<Self, AccountError> {
        let site = raw.trim().to_ascii_lowercase();
        if site.is_empty() || site.len() > MAX_SITE_ID_LEN {
            return Err(AccountError::SiteIdInvalid);
        }
        let legal = site
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.');
        let edges_ok = !site.starts_with(['-', '.']) && !site.ends_with(['-', '.']);
        if !legal || !edges_ok || site.contains("..") {
            return Err(AccountError::SiteIdInvalid);
        }
        Ok(Self(site))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Partition key for this site's ownership row.
    pub fn pk(&self) -> String {
        format!("S#{}", self.0)
    }

    /// Sort key for the membership row under the owner's partition.
    pub fn membership_sk(&self) -> String {
        format!("SITE#{}", self.0)
    }
}

impl fmt::Display for SiteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether a site's statistics may be read without a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    /// Only the owner may read. The default for a newly registered site.
    Private,
    /// Anyone may read, which is what Cairn's own sites did before accounts
    /// existed. Opt-in, so it is now a choice rather than an accident.
    Public,
}

impl Visibility {
    pub fn from_flag(public: bool) -> Self {
        if public { Self::Public } else { Self::Private }
    }

    pub fn is_public(self) -> bool {
        matches!(self, Self::Public)
    }
}

/// A session token. The plaintext is handed to the browser once; only its hash
/// is stored, so a dump of the table cannot be replayed as a login.
#[derive(Debug, Clone)]
pub struct SessionToken {
    plaintext: String,
    hash: String,
}

impl SessionToken {
    /// Build a token from 32 caller-supplied random bytes.
    ///
    /// The randomness is an argument rather than drawn here so this crate keeps
    /// its no-I/O property and the test below can assert on a fixed token.
    pub fn from_entropy(bytes: &[u8; 32]) -> Self {
        let plaintext = hex(bytes);
        let hash = hex(blake3::hash(plaintext.as_bytes()).as_bytes());
        Self { plaintext, hash }
    }

    /// Hash of a token presented by a browser, for looking the session up.
    pub fn hash_presented(presented: &str) -> String {
        hex(blake3::hash(presented.trim().as_bytes()).as_bytes())
    }

    /// Give this to the browser. Never stored.
    pub fn plaintext(&self) -> &str {
        &self.plaintext
    }

    /// Store this. Cannot be turned back into a usable token.
    pub fn hash(&self) -> &str {
        &self.hash
    }

    pub fn pk(hash: &str) -> String {
        format!("T#{hash}")
    }
}

/// Pull one cookie's value out of a `Cookie:` header.
///
/// Shared by the two handlers that read a session, so the parsing cannot drift
/// between "who am I" and "may I read this site".
pub fn cookie_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key.trim() == name).then(|| value.trim())
    })
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Hash a password for storage, with caller-supplied salt bytes.
pub fn hash_password(password: &str, salt: &[u8; 16]) -> Result<String, AccountError> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(AccountError::PasswordTooShort);
    }
    if password.len() > MAX_PASSWORD_LEN {
        return Err(AccountError::PasswordTooLong);
    }
    let salt = SaltString::encode_b64(salt).map_err(|_| AccountError::HashFailed)?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| AccountError::HashFailed)
}

/// Check a password against a stored hash.
///
/// Returns `false` for a malformed stored hash rather than erroring: a corrupt
/// row should fail the login, not hand the caller a distinguishable error that
/// says the account exists.
pub fn verify_password(password: &str, stored_hash: &str) -> bool {
    if password.len() > MAX_PASSWORD_LEN {
        return false;
    }
    let Ok(parsed) = PasswordHash::new(stored_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_is_normalised() {
        let email = Email::parse("  Gautam@Example.COM ").unwrap();
        assert_eq!(email.as_str(), "gautam@example.com");
        assert_eq!(email.pk(), "U#gautam@example.com");
    }

    #[test]
    fn email_rejects_rubbish() {
        for bad in ["", "nope", "a@b", "a b@c.com", "a@b.com#x", "@b.com", "a@"] {
            assert_eq!(Email::parse(bad), Err(AccountError::EmailInvalid), "{bad:?}");
        }
    }

    #[test]
    fn site_id_allows_a_hostname() {
        let site = SiteId::parse("Gautamstar.github.io").unwrap();
        assert_eq!(site.as_str(), "gautamstar.github.io");
        assert_eq!(site.pk(), "S#gautamstar.github.io");
        assert_eq!(site.membership_sk(), "SITE#gautamstar.github.io");
    }

    /// A site id ends up inside `E#{site}#{bucket}`. If `#` were legal, one
    /// site's partition could be spelled more than one way.
    #[test]
    fn site_id_cannot_contain_a_key_delimiter() {
        for bad in ["a#b", "", "-lead", "trail-", ".lead", "a..b", "has space", "up/down"] {
            assert_eq!(SiteId::parse(bad), Err(AccountError::SiteIdInvalid), "{bad:?}");
        }
        assert!(SiteId::parse(&"a".repeat(MAX_SITE_ID_LEN)).is_ok());
        assert!(SiteId::parse(&"a".repeat(MAX_SITE_ID_LEN + 1)).is_err());
    }

    #[test]
    fn password_round_trips() {
        let hash = hash_password("correct horse battery", &[7; 16]).unwrap();
        assert!(verify_password("correct horse battery", &hash));
        assert!(!verify_password("correct horse batterz", &hash));
    }

    #[test]
    fn password_hash_does_not_contain_the_password() {
        let hash = hash_password("hunter2hunter2", &[1; 16]).unwrap();
        assert!(!hash.contains("hunter2hunter2"));
    }

    #[test]
    fn password_length_is_bounded_both_ways() {
        assert_eq!(
            hash_password("short", &[0; 16]),
            Err(AccountError::PasswordTooShort)
        );
        assert_eq!(
            hash_password(&"x".repeat(MAX_PASSWORD_LEN + 1), &[0; 16]),
            Err(AccountError::PasswordTooLong)
        );
    }

    #[test]
    fn a_corrupt_stored_hash_fails_closed() {
        assert!(!verify_password("anything", "not-a-phc-string"));
        assert!(!verify_password("anything", ""));
    }

    /// The row that reaches DynamoDB must not be replayable as a login.
    #[test]
    fn only_the_token_hash_is_storable() {
        let token = SessionToken::from_entropy(&[9; 32]);
        assert_ne!(token.plaintext(), token.hash());
        assert_eq!(SessionToken::hash_presented(token.plaintext()), token.hash());
        assert_eq!(token.plaintext().len(), 64);
        assert_eq!(SessionToken::pk(token.hash()), format!("T#{}", token.hash()));
    }

    #[test]
    fn a_wrong_token_does_not_match() {
        let token = SessionToken::from_entropy(&[1; 32]);
        assert_ne!(SessionToken::hash_presented("deadbeef"), token.hash());
    }

    #[test]
    fn a_cookie_header_yields_one_value() {
        let header = "other=1; cairn_session=abc123; last=2";
        assert_eq!(cookie_value(header, "cairn_session"), Some("abc123"));
        assert_eq!(cookie_value("cairn_session=solo", "cairn_session"), Some("solo"));
        assert_eq!(cookie_value(header, "absent"), None);
        assert_eq!(cookie_value("", "cairn_session"), None);
        // A cookie whose name merely ends with ours is a different cookie.
        assert_eq!(cookie_value("not_cairn_session=x", "cairn_session"), None);
    }

    #[test]
    fn sites_are_private_until_told_otherwise() {
        assert!(!Visibility::from_flag(false).is_public());
        assert!(Visibility::from_flag(true).is_public());
    }
}
