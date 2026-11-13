//! StegoCode's core: password-protected records hidden in baseline JPEG photos.
//!
//! A host (the desktop or phone program, the browser page) admits photos with [`Cover::new`],
//! shows [`Cover::info`] and [`Cover::capacity`], hides with [`hide`] and reads with [`reveal`].
//! The library opens no file, network connection, clock or thread: the host passes bytes and a
//! [`Random`] source. Every new file is returned only after it reads back with each password and
//! each message gives the same SHA-256.
//!
//! Two modes exist ([`Mode`]): the standard mode with one record, and the decoy mode, where a
//! decoy with its own password carries the secret in the directions of its changes. The cost
//! model and the site rule are choices of the advanced view ([`Settings`]); a reader tries every
//! one, so a later default never makes older files unreadable.
//!
//! The record format is experimental until the detectability measurements are done.

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
mod os;
mod parts;
mod password;
pub mod protect;
mod random;
mod record;
mod report;
mod reveal;
mod self_test;
mod shard;
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
    Digest, FileReport, HideReport, Layer, Parameters, ReadReport, RecordReport, hex, parameters,
};
pub use reveal::{Reading, Revealed, reveal};
pub use self_test::{Check, SelfTest, full_self_test, startup_self_test};
pub use sites::SiteRule;
pub use threshold::THRESHOLD_MAX;
