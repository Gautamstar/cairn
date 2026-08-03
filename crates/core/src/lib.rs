//! Domain logic for Cairn, deliberately free of AWS, async, and I/O.
//!
//! Everything here is a pure function over its inputs. Nothing reads a clock,
//! opens a socket, or touches an environment variable: the current time, the
//! visitor's IP, and the hashing secret are all passed in by the caller. That
//! keeps the whole crate unit-testable with plain `cargo test` and makes the
//! Lambda handlers thin enough to be obviously correct.
//!
//! The privacy model lives here too, and it is enforced structurally rather
//! than by discipline. [`StoredEvent`] is the only type that reaches DynamoDB
//! and it has no field for an IP address, so "we never store IPs" is a property
//! of the type rather than a promise in a README.

pub mod aggregate;
pub mod bots;
pub mod event;
pub mod normalize;
pub mod origin;
pub mod privacy;
pub mod ua;

pub use aggregate::{Counts, Dimension};
pub use event::{EventContext, EventError, RawEvent, StoredEvent};
pub use origin::{ORIGIN_HEADER, secret_matches};
pub use privacy::{DailySalt, VisitorId};
pub use ua::{Browser, DeviceClass, Os, UserAgent};
