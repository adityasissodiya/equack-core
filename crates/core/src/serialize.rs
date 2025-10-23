//! Deterministic CBOR bytes for hashing. We use serde_cbor 0.11's to_vec;
//! our structs (no maps with unsorted keys) keep bytes stable for hashing.

use serde::Serialize;
use serde_cbor::to_vec;

pub fn canonical_cbor<T: Serialize>(value: &T) -> Vec<u8> {
    to_vec(value).expect("CBOR serialize failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize)]
    struct Demo { a: u8, b: u8 }

    #[test]
    fn identical_inputs_identical_bytes() {
        let x = Demo { a: 1, b: 2 };
        let y = Demo { a: 1, b: 2 };
        assert_eq!(canonical_cbor(&x), canonical_cbor(&y));
    }
}
