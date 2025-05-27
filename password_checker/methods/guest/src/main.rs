use risc0_zkvm::guest::env;
use sha2::{Sha256, Digest};

fn main() {
    // TODO: Implement your guest code here

    // read the input
    let pw: String = env::read();

    // TODO: do something with the input
    let mut is_ok = false;
    for ch in pw.chars(){
        if ch.is_ascii_punctuation(){
            is_ok = true;
        }
    }

    // if !is_ok{
    //     panic!();
    // }

    // write public output to the journal
    let digest: [u8;32] = Sha256::digest(pw.as_bytes()).into();
    env::commit(&digest);
}
