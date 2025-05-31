// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use garbling_core::{CircuitInput, LabelInputs, garble_ckt};
use risc0_zkvm::guest::env;

fn main(){
   let circuit_input: CircuitInput = env::read();

   let label_input:LabelInputs = env::read();

   let out = garble_ckt(circuit_input, label_input);

   env::commit(&out);

    
}

