//! Stripe webhooks: proving a request came from Stripe, and reading the two
//! events that change what an account has paid for.
//!
//! Pure functions, like the rest of this crate. The clock and the signing
//! secret are arguments, so the signature check is testable against a vector
//! computed outside this code.
//!
//! ## The flow
//!
//! Upgrading is a Stripe Payment Link, not an embedded checkout: Stripe hosts
//! the card form, so no card data or Stripe API key ever touches this system.
//! The link carries `client_reference_id`, which Stripe echoes back in
//! `checkout.session.completed`. That is how a payment finds its account.
//!
//! The reference is random and stored, not derived from the email. Payment
//! Links only accept `[A-Za-z0-9_-]`, so an email cannot be passed directly,
//! and a hash of one would be guessable: anyone who knew an address could
//! attach their own subscription to it and later cancel it to downgrade the
//! real owner. A random reference is only ever shown to the account it
//! belongs to.

use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;

use crate::account::Plan;

/// How old a signed webhook may be. Stripe's own libraries use five minutes;
/// it bounds how long a captured request stays replayable.
pub const SIGNATURE_TOLERANCE_SECS: i64 = 300;

/// A billing reference from 16 caller-supplied random bytes.
pub fn billing_ref(entropy: &[u8; 16]) -> String {
    let mut out = String::with_capacity(32);
    for byte in entropy {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Whether a billing reference is shaped like one this system issued.
/// Checked before it is used as a key component.
pub fn is_billing_ref(raw: &str) -> bool {
    raw.len() == 32
        && raw
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

pub fn billing_ref_pk(reference: &str) -> String {
    format!("BILLREF#{reference}")
}

pub fn subscription_pk(subscription: &str) -> String {
    format!("SUB#{subscription}")
}

/// Verify a `Stripe-Signature` header against the raw request body.
///
/// The header looks like `t=1700000000,v1=abc…,v1=def…`. Stripe signs
/// `"{t}.{body}"` with HMAC-SHA256 and may send several `v1` values while a
/// secret is being rolled, so any one matching is enough. The comparison is
/// constant-time via `Mac::verify_slice`.
pub fn verify_signature(header: &str, body: &[u8], secret: &str, now: i64) -> bool {
    let mut timestamp: Option<i64> = None;
    let mut candidates = Vec::new();
    for part in header.split(',') {
        let Some((key, value)) = part.trim().split_once('=') else {
            continue;
        };
        match key {
            "t" => timestamp = value.parse().ok(),
            "v1" => candidates.push(value),
            _ => {}
        }
    }

    let Some(t) = timestamp else {
        return false;
    };
    if (now - t).abs() > SIGNATURE_TOLERANCE_SECS {
        return false;
    }

    candidates.into_iter().any(|candidate| {
        let Some(expected) = decode_hex(candidate) else {
            return false;
        };
        let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret.as_bytes()) else {
            return false;
        };
        mac.update(t.to_string().as_bytes());
        mac.update(b".");
        mac.update(body);
        mac.verify_slice(&expected).is_ok()
    })
}

fn decode_hex(raw: &str) -> Option<Vec<u8>> {
    if raw.len() % 2 != 0 {
        return None;
    }
    (0..raw.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(raw.get(i..i + 2)?, 16).ok())
        .collect()
}

/// The events that change an account's plan. Everything else Stripe sends is
/// [`BillingEvent::Ignored`] and answered with a 200 so it is not retried.
#[derive(Debug, PartialEq, Eq)]
pub enum BillingEvent {
    /// A Payment Link checkout finished and money was taken.
    CheckoutCompleted {
        reference: String,
        payment_link: String,
        subscription: String,
        customer: String,
    },
    /// A subscription is over: cancelled at period end, or given up on after
    /// failed payments. Either way the account goes back to free.
    SubscriptionEnded {
        subscription: String,
    },
    Ignored,
}

#[derive(Deserialize)]
struct Envelope {
    #[serde(rename = "type")]
    kind: String,
    data: Data,
}

#[derive(Deserialize)]
struct Data {
    object: Object,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Object {
    id: Option<String>,
    client_reference_id: Option<String>,
    payment_link: Option<String>,
    subscription: Option<String>,
    customer: Option<String>,
    payment_status: Option<String>,
}

impl BillingEvent {
    /// Parse a verified webhook body. `None` means it was not an event at all;
    /// an event this system does not act on is `Some(Ignored)`.
    pub fn parse(body: &[u8]) -> Option<Self> {
        let envelope: Envelope = serde_json::from_slice(body).ok()?;
        let object = envelope.data.object;

        Some(match envelope.kind.as_str() {
            "checkout.session.completed" => {
                // `unpaid` happens with delayed payment methods. Granting a plan
                // before the money arrives would mean a failed bank debit still
                // bought a month of service.
                let settled = matches!(
                    object.payment_status.as_deref(),
                    Some("paid" | "no_payment_required")
                );
                match (
                    settled,
                    object.client_reference_id,
                    object.payment_link,
                    object.subscription,
                    object.customer,
                ) {
                    (
                        true,
                        Some(reference),
                        Some(payment_link),
                        Some(subscription),
                        Some(customer),
                    ) => Self::CheckoutCompleted {
                        reference,
                        payment_link,
                        subscription,
                        customer,
                    },
                    _ => Self::Ignored,
                }
            }
            "customer.subscription.deleted" => match object.id {
                Some(subscription) => Self::SubscriptionEnded { subscription },
                None => Self::Ignored,
            },
            _ => Self::Ignored,
        })
    }
}

/// Which plan a Payment Link sells, from configuration.
///
/// The plan is decided by the link Stripe says was paid, never by anything in
/// the URL the customer followed. `client_reference_id` is editable in a
/// browser's address bar; `payment_link` in the webhook is not.
pub fn plan_for_link(payment_link: &str, starter_link: &str, pro_link: &str) -> Option<Plan> {
    if payment_link.is_empty() {
        None
    } else if payment_link == starter_link {
        Some(Plan::Starter)
    } else if payment_link == pro_link {
        Some(Plan::Pro)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "whsec_test_secret";
    const BODY: &[u8] = br#"{"id":"evt_1","type":"ping"}"#;
    const T: i64 = 1_700_000_000;
    /// Computed with Python's `hmac` module, not with this code, so the test
    /// is not checking the implementation against itself.
    const SIG: &str = "74a11abdd08483d064a2a1571e7881b084c522f9f3ccd0b800ec8c74aba47fc2";

    fn header(sig: &str) -> String {
        format!("t={T},v1={sig}")
    }

    #[test]
    fn a_genuine_signature_verifies() {
        assert!(verify_signature(&header(SIG), BODY, SECRET, T));
        assert!(verify_signature(&header(SIG), BODY, SECRET, T + 299));
    }

    #[test]
    fn a_tampered_body_does_not() {
        let tampered = br#"{"id":"evt_1","type":"pong"}"#;
        assert!(!verify_signature(&header(SIG), tampered, SECRET, T));
    }

    #[test]
    fn the_wrong_secret_does_not() {
        assert!(!verify_signature(&header(SIG), BODY, "whsec_other", T));
    }

    #[test]
    fn an_old_signature_is_a_replay() {
        assert!(!verify_signature(
            &header(SIG),
            BODY,
            SECRET,
            T + SIGNATURE_TOLERANCE_SECS + 1
        ));
        assert!(!verify_signature(
            &header(SIG),
            BODY,
            SECRET,
            T - SIGNATURE_TOLERANCE_SECS - 1
        ));
    }

    #[test]
    fn any_v1_may_match_during_a_secret_roll() {
        let rolled = format!("t={T},v1={},v1={SIG}", "00".repeat(32));
        assert!(verify_signature(&rolled, BODY, SECRET, T));
    }

    #[test]
    fn malformed_headers_fail_closed() {
        for bad in [
            "",
            "garbage",
            "v1=abc",
            &format!("t=notanumber,v1={SIG}"),
            &format!("t={T}"),
            &format!("t={T},v1=zz"),
        ] {
            assert!(!verify_signature(bad, BODY, SECRET, T), "{bad:?}");
        }
    }

    #[test]
    fn a_completed_checkout_is_read() {
        let body = br#"{"type":"checkout.session.completed","data":{"object":{
            "id":"cs_1","client_reference_id":"0123456789abcdef0123456789abcdef",
            "payment_link":"plink_starter","subscription":"sub_1","customer":"cus_1",
            "payment_status":"paid","mode":"subscription"}}}"#;
        assert_eq!(
            BillingEvent::parse(body),
            Some(BillingEvent::CheckoutCompleted {
                reference: "0123456789abcdef0123456789abcdef".into(),
                payment_link: "plink_starter".into(),
                subscription: "sub_1".into(),
                customer: "cus_1".into(),
            })
        );
    }

    #[test]
    fn an_unpaid_checkout_grants_nothing() {
        let body = br#"{"type":"checkout.session.completed","data":{"object":{
            "client_reference_id":"0123456789abcdef0123456789abcdef","payment_link":"plink_starter",
            "subscription":"sub_1","customer":"cus_1","payment_status":"unpaid"}}}"#;
        assert_eq!(BillingEvent::parse(body), Some(BillingEvent::Ignored));
    }

    #[test]
    fn a_cancellation_is_read() {
        let body = br#"{"type":"customer.subscription.deleted","data":{"object":{"id":"sub_9","customer":"cus_1"}}}"#;
        assert_eq!(
            BillingEvent::parse(body),
            Some(BillingEvent::SubscriptionEnded {
                subscription: "sub_9".into()
            })
        );
    }

    #[test]
    fn other_events_are_ignored_not_rejected() {
        let body = br#"{"type":"invoice.paid","data":{"object":{"id":"in_1"}}}"#;
        assert_eq!(BillingEvent::parse(body), Some(BillingEvent::Ignored));
        assert_eq!(BillingEvent::parse(b"not json"), None);
    }

    #[test]
    fn the_plan_comes_from_the_link_stripe_charged() {
        assert_eq!(
            plan_for_link("plink_s", "plink_s", "plink_p"),
            Some(Plan::Starter)
        );
        assert_eq!(
            plan_for_link("plink_p", "plink_s", "plink_p"),
            Some(Plan::Pro)
        );
        assert_eq!(plan_for_link("plink_other", "plink_s", "plink_p"), None);
        // An unconfigured link must never match an empty payment_link.
        assert_eq!(plan_for_link("", "", ""), None);
    }

    #[test]
    fn billing_refs_are_unguessable_hex_and_validated() {
        let reference = billing_ref(&[0xab; 16]);
        assert_eq!(reference.len(), 32);
        assert!(is_billing_ref(&reference));
        assert!(!is_billing_ref("gautam@example.com"));
        assert!(!is_billing_ref("ABABABABABABABABABABABABABABABAB"));
        assert!(!is_billing_ref(&"a".repeat(31)));
        assert_eq!(billing_ref_pk(&reference), format!("BILLREF#{reference}"));
        assert_eq!(subscription_pk("sub_1"), "SUB#sub_1");
    }
}
