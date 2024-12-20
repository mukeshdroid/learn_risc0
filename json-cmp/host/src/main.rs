// These constants represent the RISC-V ELF and the image ID generated by risc0-build.
// The ELF is used for proving and the ID is used for verification.
use methods::{
    GUEST_JSON_CMP_ELF, GUEST_JSON_CMP_ID
};
use risc0_zkvm::{default_prover, ExecutorEnv};
use json_core::Outputs;

fn main() {
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    // An executor environment describes the configurations for the zkVM
    // including program inputs.
    // An default ExecutorEnv can be created like so:
    // `let env = ExecutorEnv::builder().build().unwrap();`
    // However, this `env` does not have any inputs.
    //
    // To add guest input to the executor environment, use
    // ExecutorEnvBuilder::write().
    // To access this method, you'll need to use ExecutorEnv::builder(), which
    // creates an ExecutorEnvBuilder. When you're done adding input, call
    // ExecutorEnvBuilder::build().

    //read the two json files
    let file1 = include_str!("../../res/file1.json").to_string();
    let file2 = include_str!("../../res/file2.json").to_string();

    let input = (file1,file2);

    let env = ExecutorEnv::builder()
        .write(&input)
        .unwrap()
        .build()
        .unwrap();

    // Obtain the default prover.
    let prover = default_prover();

    // Proof information by proving the specified ELF binary.
    // This struct contains the receipt along with statistics about execution of the guest
    let prove_info = prover
        .prove(env, GUEST_JSON_CMP_ELF)
        .unwrap();

    // extract the receipt.
    let receipt = prove_info.receipt;


    let out: Outputs = receipt.journal.decode().unwrap();

    if out.have_same_critical_val{
        println!("file1 with hash {} \n and file2 with hash {} both contain the same value in the field 'critical value'",out.file1hash,out.file2hash);
    }else{
        println!("file1 with hash {} \n and file2 with hash {} do NOT contain the same value in the field 'critical value'",out.file1hash,out.file2hash);
    }

    // The receipt was verified at the end of proving, but the below code is an
    // example of how someone else could verify this receipt.
    receipt
        .verify(GUEST_JSON_CMP_ID)
        .unwrap();
}
