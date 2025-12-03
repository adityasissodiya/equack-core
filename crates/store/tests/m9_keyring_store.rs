// crates/store/tests/m9_keyring_store.rs
//! M9 keyring persistence tests for ecac-store.
//!
//! These tests exercise the explicit keyring API on `Store`:
//!   - `put_tag_key(tag, version, key)`
//!   - `get_tag_key(tag, version)`
//!   - `max_key_version_for_tag(tag)`
//!
//! They assert that:
//!   1. Keys written via `put_tag_key` survive close + reopen.
//!   2. `get_tag_key` returns the exact bytes written, or None for missing entries.
//!   3. `max_key_version_for_tag` tracks the highest version per tag and ignores other tags.
//!   4. Overwriting the same (tag,version) updates the value without changing max-version semantics.

use anyhow::Result;
use ecac_store::{Store, StoreOptions};
use tempfile::TempDir;

/// Helper to open a Store in a temp directory with default options.
fn open_store(dir: &std::path::Path) -> Result<Store> {
    let opts = StoreOptions::default();
    Store::open(dir, opts)
}

#[test]
fn put_get_tag_key_roundtrip_across_reopen() -> Result<()> {
    let tmp = TempDir::new()?;
    let dir = tmp.path().to_path_buf();

    // Fixed deterministic keys for testing.
    let key_v1 = [0x11u8; 32];
    let key_v2 = [0x22u8; 32];

    // First open: write two versions for the same tag.
    {
        let store = open_store(&dir)?;
        store.put_tag_key("confidential", 1, &key_v1)?;
        store.put_tag_key("confidential", 2, &key_v2)?;
    }

    // Second open: ensure keys are still present and exact.
    let store2 = open_store(&dir)?;

    let got_v1 = store2
        .get_tag_key("confidential", 1)?
        .expect("expected key for (confidential,1) after reopen");
    let got_v2 = store2
        .get_tag_key("confidential", 2)?
        .expect("expected key for (confidential,2) after reopen");

    assert_eq!(
        got_v1, key_v1,
        "keyring must preserve exact bytes for (confidential,1)"
    );
    assert_eq!(
        got_v2, key_v2,
        "keyring must preserve exact bytes for (confidential,2)"
    );

    // Non-existent tag/version combinations must return None.
    assert!(
        store2.get_tag_key("other_tag", 1)?.is_none(),
        "unrelated tag must not have a key"
    );
    assert!(
        store2.get_tag_key("confidential", 3)?.is_none(),
        "future version without put_tag_key must not exist in keyring"
    );

    Ok(())
}

#[test]
fn max_key_version_tracks_highest_per_tag() -> Result<()> {
    let tmp = TempDir::new()?;
    let dir = tmp.path().to_path_buf();

    let key_conf_v5 = [0x33u8; 32];
    let key_conf_v7 = [0x44u8; 32];
    let key_hv_v3 = [0x55u8; 32];

    {
        let store = open_store(&dir)?;

        // Two versions for "confidential" and one for "hv".
        store.put_tag_key("confidential", 5, &key_conf_v5)?;
        store.put_tag_key("confidential", 7, &key_conf_v7)?;
        store.put_tag_key("hv", 3, &key_hv_v3)?;
    }

    let store2 = open_store(&dir)?;

    let max_conf = store2
        .max_key_version_for_tag("confidential")?
        .expect("expected some max version for tag=confidential");
    let max_hv = store2
        .max_key_version_for_tag("hv")?
        .expect("expected some max version for tag=hv");
    let max_unknown = store2.max_key_version_for_tag("unknown_tag")?;

    assert_eq!(
        max_conf, 7,
        "max_key_version_for_tag(confidential) must track the highest version"
    );
    assert_eq!(
        max_hv, 3,
        "max_key_version_for_tag(hv) must track the highest version"
    );
    assert!(
        max_unknown.is_none(),
        "max_key_version_for_tag on a tag with no keys must return None"
    );

    Ok(())
}

#[test]
fn put_tag_key_overwrites_value_for_same_version() -> Result<()> {
    let tmp = TempDir::new()?;
    let dir = tmp.path().to_path_buf();

    let key_v1_old = [0xAAu8; 32];
    let key_v1_new = [0xBBu8; 32];

    {
        let store = open_store(&dir)?;

        // Write v1, then overwrite v1 with a different key.
        store.put_tag_key("confidential", 1, &key_v1_old)?;
        store.put_tag_key("confidential", 1, &key_v1_new)?;
    }

    let store2 = open_store(&dir)?;

    // get_tag_key must see the *latest* value for (tag,1).
    let got = store2
        .get_tag_key("confidential", 1)?
        .expect("expected key for (confidential,1) after overwrite");
    assert_eq!(
        got, key_v1_new,
        "put_tag_key for the same (tag,version) must overwrite the stored value"
    );

    // max_key_version_for_tag should still be 1, not e.g. incremented.
    let max_conf = store2
        .max_key_version_for_tag("confidential")?
        .expect("expected some max version for tag=confidential");
    assert_eq!(
        max_conf, 1,
        "overwriting an existing version must not change max_key_version_for_tag"
    );

    Ok(())
}
