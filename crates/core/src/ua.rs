//! Browser, OS, and device classification from a user agent string.
//!
//! Hand-rolled on purpose. A full UA database like `woothee` or `uap-core`
//! carries thousands of regexes and megabytes of tables, which on Lambda is
//! binary size, and binary size is cold-start latency, and cold-start latency
//! is the number this project exists to keep small. Cairn needs six browser
//! buckets and three device buckets for a dashboard, not exact version
//! detection, so roughly sixty lines of substring matching buys everything that
//! actually gets displayed.
//!
//! Known limits, since they affect the numbers on the dashboard:
//!
//! - iPadOS 13 and later reports itself as desktop Safari on macOS. Apple did
//!   this deliberately and it is not detectable from the UA string alone, so
//!   some iPads land in the desktop bucket.
//! - User agents are self-reported and freely spoofable. These are traffic
//!   proportions, not identity claims, and nothing security-relevant is built
//!   on them.

use serde::Serialize;

use crate::bots;

/// A user agent string, lowercased once and then classified repeatedly.
///
/// The lowercasing is the only allocation in the whole ingest hot path, which
/// is why it happens here once rather than inside each classifier.
#[derive(Debug, Clone)]
pub struct UserAgent {
    lower: String,
}

impl UserAgent {
    pub fn parse(raw: &str) -> Self {
        Self {
            lower: raw.to_ascii_lowercase(),
        }
    }

    /// Whether this request should be excluded from analytics entirely.
    pub fn is_bot(&self) -> bool {
        bots::is_bot_lower(&self.lower)
    }

    pub fn browser(&self) -> Browser {
        Browser::from_lower(&self.lower)
    }

    pub fn os(&self) -> Os {
        Os::from_lower(&self.lower)
    }

    /// Device class, using the viewport width the tracker reports as a
    /// tiebreaker when the user agent gives nothing away.
    pub fn device(&self, viewport_width: Option<u32>) -> DeviceClass {
        DeviceClass::from_lower(&self.lower, viewport_width)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Browser {
    Chrome,
    Edge,
    Firefox,
    Safari,
    Opera,
    Samsung,
    Other,
}

impl Browser {
    /// Order is the entire difficulty of user agent sniffing, and it is not
    /// arbitrary. For historical compatibility reasons Edge's UA contains
    /// `chrome`, and Chrome's contains `safari`. Checking in any order other
    /// than most-specific-first would report every Edge user as Chrome and
    /// every Chrome user as Safari.
    fn from_lower(ua: &str) -> Self {
        if ua.contains("edg/")
            || ua.contains("edge/")
            || ua.contains("edga/")
            || ua.contains("edgios/")
        {
            Self::Edge
        } else if ua.contains("opr/") || ua.contains("opera") {
            Self::Opera
        } else if ua.contains("samsungbrowser") {
            Self::Samsung
        } else if ua.contains("firefox") || ua.contains("fxios") {
            Self::Firefox
        } else if ua.contains("chrome") || ua.contains("chromium") || ua.contains("crios") {
            Self::Chrome
        } else if ua.contains("safari") {
            Self::Safari
        } else {
            Self::Other
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Chrome => "Chrome",
            Self::Edge => "Edge",
            Self::Firefox => "Firefox",
            Self::Safari => "Safari",
            Self::Opera => "Opera",
            Self::Samsung => "Samsung Internet",
            Self::Other => "Other",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Os {
    Windows,
    MacOs,
    Ios,
    Android,
    Linux,
    ChromeOs,
    Other,
}

impl Os {
    /// Ordering matters here too, for the same reason. iOS user agents contain
    /// `like mac os x`, and Android user agents contain `linux`, so the
    /// specific platform has to be checked before the general one it embeds.
    fn from_lower(ua: &str) -> Self {
        if ua.contains("iphone") || ua.contains("ipad") || ua.contains("ipod") {
            Self::Ios
        } else if ua.contains("android") {
            Self::Android
        } else if ua.contains("windows") {
            Self::Windows
        } else if ua.contains("cros") {
            Self::ChromeOs
        } else if ua.contains("mac os x") || ua.contains("macintosh") {
            Self::MacOs
        } else if ua.contains("linux") || ua.contains("x11") {
            Self::Linux
        } else {
            Self::Other
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Windows => "Windows",
            Self::MacOs => "macOS",
            Self::Ios => "iOS",
            Self::Android => "Android",
            Self::Linux => "Linux",
            Self::ChromeOs => "ChromeOS",
            Self::Other => "Other",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceClass {
    Desktop,
    Mobile,
    Tablet,
}

/// Viewport width below which a device is treated as a phone.
const MOBILE_MAX_WIDTH: u32 = 768;
/// Viewport width below which a device is treated as a tablet.
const TABLET_MAX_WIDTH: u32 = 1024;

impl DeviceClass {
    fn from_lower(ua: &str, viewport_width: Option<u32>) -> Self {
        // Android's convention is that `mobile` present means phone and absent
        // means tablet, which is backwards from what the words suggest but is
        // what Google documented and what shipped.
        if ua.contains("ipad") || (ua.contains("android") && !ua.contains("mobile")) {
            Self::Tablet
        } else if ua.contains("mobile") || ua.contains("iphone") || ua.contains("ipod") {
            Self::Mobile
        } else {
            // Nothing in the UA settled it, so fall back to the viewport width
            // the tracker reported. This is what rescues the iPadOS case above,
            // at least when the browser is not full screen on a large display.
            match viewport_width {
                Some(w) if w < MOBILE_MAX_WIDTH => Self::Mobile,
                Some(w) if w < TABLET_MAX_WIDTH => Self::Tablet,
                _ => Self::Desktop,
            }
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Desktop => "Desktop",
            Self::Mobile => "Mobile",
            Self::Tablet => "Tablet",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHROME_WIN: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                              (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
    const EDGE_WIN: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                            (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0";
    const SAFARI_MAC: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
                              AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 \
                              Safari/605.1.15";
    const FIREFOX_LINUX: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 \
                                 Firefox/130.0";
    const SAFARI_IPHONE: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) \
                                 AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 \
                                 Mobile/15E148 Safari/604.1";
    const CHROME_ANDROID: &str = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 \
                                  (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36";
    const ANDROID_TABLET: &str = "Mozilla/5.0 (Linux; Android 13; SM-X710) AppleWebKit/537.36 \
                                  (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
    const SAFARI_IPAD: &str = "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) \
                               AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 \
                               Mobile/15E148 Safari/604.1";

    fn ua(raw: &str) -> UserAgent {
        UserAgent::parse(raw)
    }

    /// The regression that motivates the ordering in `Browser::from_lower`.
    /// Edge advertises Chrome and Chrome advertises Safari, so a naive
    /// implementation misfiles both.
    #[test]
    fn edge_is_not_reported_as_chrome() {
        assert_eq!(ua(EDGE_WIN).browser(), Browser::Edge);
        assert_eq!(ua(CHROME_WIN).browser(), Browser::Chrome);
    }

    #[test]
    fn chrome_is_not_reported_as_safari() {
        assert_eq!(ua(CHROME_WIN).browser(), Browser::Chrome);
        assert_eq!(ua(SAFARI_MAC).browser(), Browser::Safari);
    }

    #[test]
    fn browsers_classify() {
        assert_eq!(ua(FIREFOX_LINUX).browser(), Browser::Firefox);
        assert_eq!(ua(SAFARI_IPHONE).browser(), Browser::Safari);
        assert_eq!(
            ua(
                "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) \
                SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36"
            )
            .browser(),
            Browser::Samsung
        );
        assert_eq!(
            ua(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
                Chrome/140.0.0.0 Safari/537.36 OPR/106.0.0.0"
            )
            .browser(),
            Browser::Opera
        );
    }

    /// iOS embeds `like mac os x` and Android embeds `linux`, so both would be
    /// misfiled by a check that tested the general platform first.
    #[test]
    fn ios_is_not_reported_as_macos() {
        assert_eq!(ua(SAFARI_IPHONE).os(), Os::Ios);
        assert_eq!(ua(SAFARI_MAC).os(), Os::MacOs);
    }

    #[test]
    fn android_is_not_reported_as_linux() {
        assert_eq!(ua(CHROME_ANDROID).os(), Os::Android);
        assert_eq!(ua(FIREFOX_LINUX).os(), Os::Linux);
    }

    #[test]
    fn operating_systems_classify() {
        assert_eq!(ua(CHROME_WIN).os(), Os::Windows);
        assert_eq!(ua(SAFARI_IPAD).os(), Os::Ios);
        assert_eq!(
            ua(
                "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) \
                Chrome/140.0.0.0 Safari/537.36"
            )
            .os(),
            Os::ChromeOs
        );
    }

    #[test]
    fn devices_classify_from_user_agent() {
        assert_eq!(ua(CHROME_WIN).device(None), DeviceClass::Desktop);
        assert_eq!(ua(SAFARI_IPHONE).device(None), DeviceClass::Mobile);
        assert_eq!(ua(CHROME_ANDROID).device(None), DeviceClass::Mobile);
        assert_eq!(ua(SAFARI_IPAD).device(None), DeviceClass::Tablet);
    }

    /// Android signals tablet by *omitting* `mobile`, which is easy to get
    /// backwards.
    #[test]
    fn android_without_mobile_token_is_a_tablet() {
        assert_eq!(ua(ANDROID_TABLET).device(None), DeviceClass::Tablet);
    }

    #[test]
    fn viewport_width_breaks_ties_when_ua_is_silent() {
        // Desktop-shaped UA in a phone-sized viewport: trust the viewport.
        assert_eq!(ua(SAFARI_MAC).device(Some(390)), DeviceClass::Mobile);
        assert_eq!(ua(SAFARI_MAC).device(Some(834)), DeviceClass::Tablet);
        assert_eq!(ua(SAFARI_MAC).device(Some(1920)), DeviceClass::Desktop);
    }

    /// A UA that already says `mobile` should not be overridden by a wide
    /// viewport, which can happen on a phone in landscape.
    #[test]
    fn explicit_mobile_ua_beats_viewport_width() {
        assert_eq!(ua(CHROME_ANDROID).device(Some(1920)), DeviceClass::Mobile);
    }

    #[test]
    fn bot_detection_reuses_the_lowercased_string() {
        assert!(ua("Googlebot/2.1").is_bot());
        assert!(!ua(CHROME_WIN).is_bot());
    }

    #[test]
    fn enums_serialize_as_snake_case() {
        assert_eq!(serde_json::to_string(&Browser::Edge).unwrap(), "\"edge\"");
        assert_eq!(serde_json::to_string(&Os::MacOs).unwrap(), "\"mac_os\"");
        assert_eq!(
            serde_json::to_string(&DeviceClass::Tablet).unwrap(),
            "\"tablet\""
        );
    }
}
