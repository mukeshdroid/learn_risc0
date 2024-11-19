use risc0_zkvm::sha::Digest;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Outputs {
    pub file1hash: Digest,
    pub file2hash: Digest,
    pub have_same_critical_val: bool,
}