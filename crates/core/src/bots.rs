//! Bot filtering.
//!
//! Roughly half of raw web traffic is automated, so an unfiltered pageview
//! count is not wrong by a rounding error, it is wrong by a factor. Filtering
//! is what makes the numbers mean anything.
//!
//! The bias here is deliberate: when a user agent is ambiguous, drop it. An
//! analytics tool that undercounts is mildly annoying, whereas one that
//! overcounts is actively misleading, and the whole point of self-hosting is to
//! trust the number. Substring matching on `bot` will occasionally catch a real
//! device (Cubot makes Android phones), and that trade is accepted knowingly.

/// Substrings that mark a request as automated, all lowercase.
///
/// Three groups: self-declaring crawlers, HTTP clients and scripting libraries
/// that never represent a human, and link-preview fetchers. The last group is
/// easy to forget and matters more than it looks: every time a link gets pasted
/// into Slack or iMessage, a fetcher hits the page and would otherwise be
/// counted as a visitor.
const BOT_MARKERS: &[&str] = &[
    // Self-declaring crawlers and search engines
    "bot",
    "crawl",
    "spider",
    "slurp",
    "archiver",
    "scraper",
    "yandex",
    "baidu",
    // SEO and monitoring suites
    "ahrefs",
    "semrush",
    "mj12",
    "dotbot",
    "screaming frog",
    "pingdom",
    "uptimerobot",
    "gtmetrix",
    "lighthouse",
    "statuscake",
    "site24x7",
    // Headless browsers and automation drivers
    "headlesschrome",
    "phantomjs",
    "puppeteer",
    "playwright",
    "selenium",
    "electron/",
    // Bare HTTP clients: never a person
    "curl/",
    "wget/",
    "libwww",
    "http-client",
    "httpclient",
    "python-requests",
    "python-urllib",
    "aiohttp",
    "go-http-client",
    "okhttp",
    "java/",
    "axios/",
    "node-fetch",
    "got/",
    "postmanruntime",
    "insomnia",
    "guzzlehttp",
    "reqwest",
    // Link-preview fetchers
    "facebookexternalhit",
    "twitterbot",
    "slackbot",
    "discordbot",
    "telegrambot",
    "whatsapp",
    "linkedinbot",
    "embedly",
    "skypeuripreview",
    "bingpreview",
    "redditbot",
    "applebot",
    "vkshare",
    "quora link preview",
];

/// Whether this user agent should be excluded from analytics.
pub fn is_bot(user_agent: &str) -> bool {
    is_bot_lower(&user_agent.to_ascii_lowercase())
}

/// As [`is_bot`], for a user agent that has already been lowercased.
///
/// Exists so the hot path can lowercase once and reuse the result across bot
/// detection and browser, OS, and device classification.
pub(crate) fn is_bot_lower(lower: &str) -> bool {
    // An empty or absent user agent is not a browser. Every real one sends
    // something, so a blank value means a script that did not bother.
    if lower.trim().is_empty() {
        return true;
    }
    BOT_MARKERS.iter().any(|marker| lower.contains(marker))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHROME: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                          (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
    const IPHONE_SAFARI: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) \
                                 AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 \
                                 Mobile/15E148 Safari/604.1";

    #[test]
    fn real_browsers_pass() {
        assert!(!is_bot(CHROME));
        assert!(!is_bot(IPHONE_SAFARI));
        assert!(!is_bot(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 \
             (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
        ));
    }

    #[test]
    fn crawlers_are_caught() {
        assert!(is_bot(
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        ));
        assert!(is_bot(
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
        ));
        assert!(is_bot(
            "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)"
        ));
    }

    #[test]
    fn http_clients_are_caught() {
        assert!(is_bot("curl/8.4.0"));
        assert!(is_bot("python-requests/2.31.0"));
        assert!(is_bot("Go-http-client/2.0"));
        assert!(is_bot("PostmanRuntime/7.35.0"));
    }

    /// These carry browser-shaped user agents and would otherwise sail through.
    #[test]
    fn link_preview_fetchers_are_caught() {
        assert!(is_bot("facebookexternalhit/1.1"));
        assert!(is_bot(
            "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)"
        ));
        assert!(is_bot("WhatsApp/2.23.20.0"));
        assert!(is_bot(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
             (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36"
        ));
    }

    #[test]
    fn missing_user_agent_is_a_bot() {
        assert!(is_bot(""));
        assert!(is_bot("   "));
    }

    #[test]
    fn matching_is_case_insensitive() {
        assert!(is_bot("GOOGLEBOT"));
        assert!(is_bot("CURL/8.4.0"));
    }
}
