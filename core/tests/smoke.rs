//! Smoke tests for the `mitm-core` crate skeleton.

use mitm_core::crate_name;

#[test]
fn exposes_crate_identity() {
    assert_eq!(crate_name(), "mitm-core");
}
