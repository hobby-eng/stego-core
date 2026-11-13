//! The coding algorithms: cost models and syndrome codes. They work on quantized coefficients
//! only and never read or write a file; the detectability measurements use them directly.

pub mod jcrfw;
pub mod jmipod;
pub mod juniward;
pub mod model;
pub mod policy;
pub mod stc;
pub mod uerd;
pub mod wetpaper;
