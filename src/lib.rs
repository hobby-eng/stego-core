//! StegoCode's core: password-protected records hidden in baseline JPEG photos.
//!
//! The host admits photos with [`Cover::new`], hides with [`hide`] and reads with [`reveal`]. The
//! library opens no file, network, clock or thread, and returns a file only after it reads back
//! with every password. The record format is experimental until the detectability tests are done.

#![deny(unsafe_code)]

pub mod algorithm;
mod coding;
mod content;
mod cover;
mod error;
mod extend;
mod fit;
mod hide;
mod inspect;
mod jpeg;
mod keys;
mod mode;
mod parts;
mod password;
mod plain;
/// Pages for secrets and the isolation of the process, from the workspace's shared crate
/// `secret-protection-core`: [`protect::Secret`], [`protect::Isolation`], [`protect::Worker`] and the
/// rest.
pub use secret_protection_core as protect;
mod random;
mod record;
mod report;
mod reveal;
mod self_test;
mod sites;
mod threshold;

pub use content::{Content, FILE_NAME_MAX, Kind};
pub use cover::{Capacity, Cover, PhotoInfo, RECOMMENDED_BPNZAC, memory_estimate};
pub use error::StegoError;
pub use extend::{Addition, ExtendReport, Extended, Membership, Place, SetError, extend};
pub use fit::{Fit, Room, fit};
pub use hide::{HideResult, Secret, hide};
pub use inspect::{Coding, Inspection, Segment, inspect};
pub use keys::{KDF_LANES, WorkFactor};
pub use mode::{CostModel, Mode, Settings};
pub use parts::CARRIERS_MAX;
pub use password::{PASSWORD_MAX, PASSWORD_MIN, Password};
pub use random::Random;
pub use report::{
    Digest, FileReport, HideReport, Layer, Locking, Parameters, ReadReport, RecordReport, hex,
    parameters,
};
pub use reveal::{Reading, Revealed, reveal};
pub use self_test::{Check, SelfTest, full_self_test, startup_self_test};
pub use sites::SiteRule;
pub use threshold::THRESHOLD_MAX;
