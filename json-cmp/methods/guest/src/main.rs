use json::parse;
use json_core::Outputs;
use risc0_zkvm::{
    guest::env,
    sha::{Impl, Sha256},
};

fn main() {
    //read data from the environment.
    //This is the data that was given to the guest program by host.
    let data : (String,String)= env::read();

    //get the hash of the two files
    let file1_hash = *Impl::hash_bytes(&data.0.as_bytes());
    let file2_hash = *Impl::hash_bytes(&data.1.as_bytes());

    //parse the contents of the two files
    let file1_contents = parse(&data.0).unwrap();
    let file2_contents = parse(&data.1).unwrap();

    //get the critical data field from both the files
    let file1_critcalcontent = file1_contents["critical_data"].as_u32().unwrap();
    let file2_critcalcontent = file2_contents["critical_data"].as_u32().unwrap();

    let have_same_critical_val = file1_critcalcontent == file2_critcalcontent;

    //commit to the Outputs
    let out = Outputs {
        file1hash: file1_hash,
        file2hash: file2_hash,
        have_same_critical_val,
    };


    // write public output to the journal
    env::commit(&out);
}
