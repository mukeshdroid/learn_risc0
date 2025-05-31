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

use serde::{Deserialize, Serialize};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;
use sha2::{Digest, Sha256};
use serde_bytes::ByteBuf;

use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Inputs {
    pub board: String,
    pub mv: String,
}

// define a seed to initialize the CS-PRNG
pub const SEED: [u8; 32] = [0; 32];

/// fixed-width 128-bit label
pub type Label = [u8; 16];

/// Struct to hold the two labels for each wires
#[derive(Clone)]
struct WireLabels {
    k0: Label,
    k1: Label,
}

/// One gate as parsed from Bristol, before garbling.
#[derive(Debug, Serialize, Deserialize)]
pub enum GateDef {
    And { in0: usize, in1: usize, out: usize },
    Xor { in0: usize, in1: usize, out: usize },
    Not { input: usize, out: usize },
}

/// Stores the circuit information after parsing the input ckt
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct CircuitInput {
    pub total_gate_count: usize,
    pub and_gate_count: usize,
    pub xor_gate_count: usize,
    pub not_gate_count: usize,
    pub total_wire_count: usize,
    pub input1_count: usize,
    pub input2_count: usize,
    pub output_wire_count: usize,
    pub gates: Vec<GateDef>,
}

impl CircuitInput {
    /// Number of primary input wires = garbler + evaluator inputs
    pub fn get_input_wire_count(&self) -> usize {
        self.input1_count + self.input2_count
    }
    /// Number of inner labels you must supply: one per AND and one per NOT
    pub fn get_inner_wire_label_count(&self) -> usize {
        self.and_gate_count + self.not_gate_count
    }
}


#[derive(Serialize, Deserialize)]
pub struct  LabelInputs{
    //global delta for free XOR
    pub delta: Label,
    // zero labels for input wires
    pub input_labels: Vec<Label>,
    // zero labels for output of AND and NOT gates
    pub inner_labels: Vec<Label>,
}


#[derive(Serialize)]
struct AndGateTable {
    gate: usize,
    in0: usize,
    in1: usize,
    out: usize,
    // four ciphertexts ordered (a=0,b=0) .. (1,1)
    table: [ByteBuf; 4],
}

#[derive(Serialize)]
struct NotGateTable {
    gate: usize,
    input: usize,
    out: usize,
    table: [ByteBuf; 2],
}

#[derive(Serialize)]
pub struct GarbledOutput {
    // // delta: String,
    // labels: Vec<[String; 2]>,
    and_tables: Vec<AndGateTable>,
    not_tables: Vec<NotGateTable>,
}

// this xors the 128 bit labels
fn xor_labels(a: &Label, b: &Label) -> Label {
    let mut r = [0u8; 16];
    for i in 0..16 {
        r[i] = a[i] ^ b[i];
    }
    r
}

/// sha256-based pad: H(ka || kb)
// This is used to get the masking value for the output gate labels
// if two gates might share the same inputs, we need to append the gate_id to the value being hashed to get differnt table entries.
// TODO: @mukesh (optimization) For Not gates, only 1 label is enough. currently, I just duplicate the same label. this function
// signature can be overloaded to handle both.
fn pad_sha(ka: &Label, kb: &Label) -> Label {
    // let mut h = Hasher::new(); //for blake3
    let mut h = Sha256::new();
    h.update(ka);
    h.update(kb);
    let digest = h.finalize(); // 32 bytes
    let mut out = [0u8; 16]; // only 16 bytes are needed since our labels are 16 bytes
    out.copy_from_slice(&digest[..16]);
    out
}

/// Parse a minimal subset of Bristol format: assumes each gate line is:
///     <AND/XOR> <u> <v> <o>
/// or, <INV> <u> <o>
fn parse_bristol<P: AsRef<Path>>(path: P) -> anyhow::Result<CircuitInput> {
    let file = File::open(path)?;
    let mut rdr = BufReader::new(file);
    let mut line = String::new();

    // line 0 - gate details: #gates #AND_gates #XOR_gates #NOT_gates
    rdr.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let total_gate_count: usize = parts.next().unwrap().parse()?;
    let and_gate_count: usize = parts.next().unwrap().parse()?;
    let xor_gate_count: usize = parts.next().unwrap().parse()?;
    let not_gate_count: usize = parts.next().unwrap().parse()?;
    line.clear();

    // line 1 – input counts: #wires #garbler_input_wires #eval_input_wires #output_wires
    rdr.read_line(&mut line)?;
    let mut ins = line.split_whitespace();
    let total_wire_count =ins.next().unwrap().parse()?; 
    let input1_count: usize = ins.next().unwrap().parse()?;
    let input2_count: usize = ins.next().unwrap().parse()?;
    let output_wire_count: usize = ins.next().unwrap().parse()?;
    line.clear();

    //store all the gates
    let mut gates = Vec::with_capacity(total_gate_count);

    // loop over lines in the ckt to parse the gate
    for _ in 0..total_gate_count {
        rdr.read_line(&mut line)?;
        let mut p = line.split_whitespace();

        // read the gate type
        let gstr = p.next().unwrap();
        
        let in_arity: usize = if gstr == "AND" || gstr == "XOR" {2} else {1};

        // collect input wires depending on in_parity of gate
        let inputs: Vec<usize> = (0..in_arity)
            .map(|_| p.next().unwrap().parse().unwrap())
            .collect::<Vec<_>>();
        let output = p.next().unwrap().parse()?;

        let gate = match gstr {
            "AND" => GateDef::And {
                in0: inputs[0],
                in1: inputs[1],
                out: output,
            },
            "XOR" => GateDef::Xor {
                in0: inputs[0],
                in1: inputs[1],
                out: output,
            },
            "INV" => GateDef::Not {
                input: inputs[0],
                out: output,
            },
            (other) => {
                anyhow::bail!("unexpected gate `{}`", other)
            }
        };
        gates.push(gate);
        line.clear();
    }

    // TODO: @mukesh (sanity checks) The gate and wire counts as claimed by header and in the circuit
    // may be inconsistent. Can we trust the input? It might be better to either validate them, or
    // compute them from circuit description as needed. For now, its ok to have all values
    // once the garbling code is done, this can be updated.
    let ckt = CircuitInput {
        total_gate_count,
        and_gate_count,
        xor_gate_count,
        not_gate_count,
        total_wire_count,
        input1_count,
        input2_count,
        output_wire_count,
        gates,
    };
    Ok(ckt)
}


pub fn garble_ckt(ckt_inputs: CircuitInput, label_inputs: LabelInputs) -> GarbledOutput {
    let wcnt = ckt_inputs.total_wire_count;
    let gcnt = ckt_inputs.total_gate_count;
    let in1 = ckt_inputs.input1_count;
    let in2 = ckt_inputs.input2_count;
    let gates = ckt_inputs.gates;

    let delta = label_inputs.delta;
    let mut inner_iter = label_inputs.inner_labels.into_iter();

    // pre-allocate wire slots
     let mut wires: Vec<Option<WireLabels>> = Vec::with_capacity(wcnt);
     // 1) load input labels
     for k0 in label_inputs.input_labels.into_iter() {
         let k1 = xor_labels(&k0, &delta);
         wires.push(Some(WireLabels { k0, k1 }));
     }
     // 2) the rest start empty
     for _ in (in1+in2)..wcnt {
         wires.push(None);
     }

    // 3) Prepare output tables
    let mut and_tables = Vec::new();
    let mut not_tables = Vec::new();

    //generate the garbled table
    // TODO: @mukesh (optimization) The input wires will always have labels. so maybe skip ensuring
    // labels for them.
    for (idx, gate) in gates.iter().enumerate() {
        match *gate {
            GateDef::Xor { in0, in1, out } => {
                // free‐XOR: just assign labels
                let lu = wires[in0].as_ref().unwrap();
                let lv = wires[in1].as_ref().unwrap();
                let k0 = xor_labels(&lu.k0, &lv.k0);
                let k1 = xor_labels(&k0, &delta);
                wires[out] = Some(WireLabels { k0, k1 });
            }

            GateDef::And { in0, in1, out } => {
                let lu = wires[in0].clone().unwrap();
                let lv = wires[in1].clone().unwrap();

                let k0_out = inner_iter.next().unwrap();
                let k1_out = xor_labels(&k0_out, &delta);
                wires[out] = Some(WireLabels { k0: k0_out, k1: k1_out });


                let mut table: [ByteBuf; 4] = Default::default();
                let combos = [(0u8, 0u8), (0, 1), (1, 0), (1, 1)];
                for (i, (a, b)) in combos.iter().enumerate() {
                    let ka = if *a == 0 { lu.k0 } else { lu.k1 };
                    let kb = if *b == 0 { lv.k0 } else { lv.k1 };
                    let out_bit = a & b;
                    let kout = if out_bit == 0 { k0_out } else { k1_out };
                    let p = pad_sha(&ka, &kb);
                    // let p = pad_poseidon(&ka, &kb);
                    let ct = xor_labels(&p, &kout);
                    table[i] = ByteBuf::from(ct.to_vec());
                }

                and_tables.push(AndGateTable {
                    gate: idx,
                    in0,
                    in1,
                    out,
                    table,
                });
            }

            GateDef::Not { input, out } => {

                let lu = wires[input].clone().unwrap();

                let k0_out = inner_iter.next().unwrap();
                let k1_out = xor_labels(&k0_out, &delta);
                wires[out] = Some(WireLabels { k0: k0_out, k1: k1_out });


                let mut table: [ByteBuf; 2] = Default::default();
                for (i, &a) in [0u8, 1].iter().enumerate() {
                    let ka = if a == 0 { lu.k0 } else { lu.k1 };
                    let out_bit = 1 - a;
                    let kout = if out_bit == 0 { k0_out } else { k1_out };
                    let p = pad_sha(&ka, &ka); // unary, duplicate
                    // let p = pad_poseidon(&ka, &ka);
                    let ct = xor_labels(&p, &kout);
                    table[i] = ByteBuf::from(ct.to_vec());
                }

                not_tables.push(NotGateTable {
                    gate: idx,
                    input,
                    out,
                    table,
                });
            }
        }
    }

    // // Collect human-readable input labels
    // let mut input_labels = Vec::with_capacity(in1 + in2);
    // for i in 0..(in1 + in2) {
    //     let wl = wires[i].clone().unwrap();
    //     input_labels.push([hex::encode(wl.k0), hex::encode(wl.k1)]);
    // }

    // // I want to output all labels for for testing. Enable for debugging
    // let mut labels_vec = Vec::with_capacity(wcnt);
    // for wire in wires.iter().take(wcnt) {
    //     let wl = wire.clone().unwrap();
    //     labels_vec.push([hex::encode(wl.k0), hex::encode(wl.k1)]);
    // }

    GarbledOutput {
        // delta: hex::encode(delta),
        // labels: input_labels,
        and_tables,
        not_tables,
    }
}

    //read the circuit
pub fn read_input() -> CircuitInput {
    // parse_bristol("simplified_example1.bristol").unwrap()
    // parse_bristol("simplified_example2.bristol").unwrap()
    parse_bristol("simplified_example3.bristol").unwrap()
}

//generate the labels
pub fn gen_labels(input_wire_count: usize, inner_wire_count: usize) -> LabelInputs{
    // The seed value is used to initialize a Chacha20 RNG which is cryptographically secure, which uses an internal 64 bit counter
    let mut rng = ChaCha12Rng::from_seed(SEED);

    //initialize delta with random value. this is the global offset required for free-xor
    let mut delta = [0u8; 16];
    rng.fill_bytes(&mut delta);

    let mut input_labels = Vec::with_capacity(input_wire_count);
     for _ in 0..input_wire_count {
         let mut k0 = [0u8;16];
         rng.fill_bytes(&mut k0);
         input_labels.push(k0);
     }


    let mut inner_labels = Vec::with_capacity(inner_wire_count);
     for _ in 0..inner_wire_count {
         let mut k0 = [0u8;16];
         rng.fill_bytes(&mut k0);
         inner_labels.push(k0);
     }

    LabelInputs { 
        delta,
        input_labels,
        inner_labels,
    }
}

