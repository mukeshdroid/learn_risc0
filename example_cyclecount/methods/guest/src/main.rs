use risc0_zkvm::guest::env;
use risc0_zkvm::guest::memory_barrier;

fn main() {
    // TODO: Implement your guest code here

    // read the input
    let iter: u32 = env::read();
            let iters = iter * 1024;
            println!("HELLO: {}", iter);

            for i in 0..iters {
                memory_barrier(&i);
            }

            env::log("jj");
            env::commit(&iter);
}
