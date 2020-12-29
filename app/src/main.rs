// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..
#![feature(proc_macro_hygiene)]

use std::collections::HashMap;
use std::time::Instant;

use failure::bail;
use merk::*;
use rand::Rng;
use serde_derive::{Deserialize, Serialize};
use sgx_types::*;
use sgx_urts::SgxEnclave;

extern "C" {
    pub fn ecall_get(
        eid: sgx_enclave_id_t,
        retval: *mut u8,
        key_ptr: *mut u8, key_len: usize,
        nonce_ptr: *mut u8, nonce_len: usize,
        value_ptr: *mut u8, value_len: *mut usize,
        sig: &mut sgx_ec256_signature_t,
    ) -> sgx_status_t;
    pub fn ecall_update(
        eid: sgx_enclave_id_t,
        retval: *mut u8,
        key_ptr: *mut u8, key_len: usize,
        op: u8, value: *mut u8, newRootHash: &Hash,
        oproof_ptr: *mut u8, oproof_len: usize,
        nproof_ptr: *mut u8, nproof_len: usize,
    ) -> sgx_status_t;
}

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

fn init_enclave() -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {secs_attr: sgx_attributes_t { flags:0, xfrm:0}, misc_select:0};
    SgxEnclave::create(ENCLAVE_FILE,
                       debug,
                       &mut launch_token,
                       &mut launch_token_updated,
                       &mut misc_attr)
}

pub type Bytes = Vec<u8>;
pub type KeyType = [u8];
pub type ValueType = Vec<u8>;

pub enum ProofType {
    Tee,
    Merkle
}

pub struct ValueWithProof {
    pub proofType: ProofType,
    pub value: Option<ValueType>,
    pub proof: Option<Bytes>, // sign of tee or merkle proof
    pub signature: Option<sgx_ec256_signature_t>,
}

impl ValueWithProof {
    pub fn new(
        proofType: ProofType, 
        value: Option<ValueType>, 
        proof: Option<Bytes>, 
        signature: Option<sgx_ec256_signature_t>
    ) -> Self {
        ValueWithProof {
            proofType,
            value,
            proof,
            signature,
        }
    }
}

pub struct CachedMerk {
    merk: Option<Merk>,
    inTee: InTee,
}


impl CachedMerk {
    pub fn new() -> Self {
        CachedMerk {
            merk: Merk::open("./merk.db").ok(),
            inTee: InTee::new(),
        }
    }

    pub fn destroy(&mut self) {
        let merk = self.merk.take();
        match merk {
            Some(m) => m.destroy().unwrap(),
            _ => (),
        };
        self.inTee.destroy();
    }

    pub fn get(&self, key: &KeyType, nonce: &Bytes) -> Result<Option<ValueType>>{
        /*
        match self.inTee.get(key, nonce) {
             Some(result) => return Ok(Some(result)),
             None => (),
        };
        */
        self.merk.as_ref().unwrap().get(key)
    }

    pub fn apply(&mut self, key: &KeyType, op: Op) -> Result<()> {
        let keyVec = key.to_vec();
        let merk = self.merk.as_mut().unwrap();
        let oldProof = merk.prove(&[keyVec.clone()])?;
        let op_clone = match &op {
            Op::Put(v) => Op::Put(v.clone()),
            Op::Delete => Op::Delete,
        };
        merk.apply(&[(keyVec.clone(), op_clone)], &[])?;
        let newProof = merk.prove(&[keyVec.clone()])?;
        let newRootHash = merk.root_hash();
        self.inTee.update(key, op, newRootHash, oldProof, newProof)
    }

    pub fn get_authorized(&self, key: &KeyType, nonce: &Bytes) -> Result<ValueWithProof>{
        if let Some((value, sign)) = self.inTee.get(key, nonce) {
            return Ok(ValueWithProof::new(
                ProofType::Tee,
                Some(value),
                None,
                Some(sign),
            ));
        }
        let merk = self.merk.as_ref().unwrap();
        let value: Option<ValueType> = merk.get(key)?;
        let keyVec = key.to_vec();
        let proof: Vec<u8> = merk.prove(&[keyVec])?;
        return Ok(ValueWithProof::new(
            ProofType::Merkle,
            value,
            Some(proof),
            None,
        ))
    }
}

struct InTee {
    enclave: Option<SgxEnclave>,
}

impl InTee {
    pub fn new() -> Self {
        let enclave = match init_enclave() {
            Ok(r) => {
                println!("[+] Init Enclave Successful {}!", r.geteid());
                Some(r)
            },
            Err(x) => {
                println!("[-] Init Enclave Failed {}!", x.as_str());
                None
            },
        };
        InTee {
            enclave,
        }
    }

    pub fn destroy(&mut self) {
        match self.enclave.take() {
            Some(enclave) => enclave.destroy(),
            None => (),
        };
    }

    pub fn update(&mut self, key: &KeyType, op: Op, newRootHash: Hash, mut oldProof: Vec<u8>, mut newProof: Vec<u8>) -> Result<()> {
        let mut retval: u8 = 0;
        let mut key = key.to_vec();
        let mut value = Vec::new();
        let op = match op {
            Op::Put(v) => {
                value = v;
                1
            },
            Op::Delete => 0,
        };
        let value_ptr = Box::into_raw(Box::new(value));
        let err_msg = failure::err_msg("no enclave");
        let result = unsafe { 
            ecall_update(self.enclave.as_ref().ok_or(err_msg)?.geteid(),
                &mut retval,
                key.as_mut_ptr(), key.len(),
                op, value_ptr as *mut u8, &newRootHash,
                oldProof.as_mut_ptr(), oldProof.len(),
                newProof.as_mut_ptr(), newProof.len(),
            ) 
        };
        let _value = unsafe { Box::from_raw(value_ptr) }; //for free
        match result {
            sgx_status_t::SGX_SUCCESS => {},
            _ => {
                println!("[-] ECALL Enclave Failed {}!", result.as_str());
                let err = failure::err_msg("update error in enclave");
                return Err(err);
            }
        };
        match retval {
            1 => Ok(()),
            0 => bail!("update error"),
            _ => panic!("return number error"),
        }
    }

    fn verify() -> Result<bool>{
        Ok(true)
    }

    pub fn get(&self, key: &KeyType, nonce: &Bytes) -> Option<(ValueType, sgx_ec256_signature_t)>{
        let mut retval: u8 = 0;
        let mut key = key.to_vec();
        let mut nonce = nonce.to_vec();
        let mut len = 1000;
        let mut value = Vec::with_capacity(len); //tmp
        let mut sig: sgx_ec256_signature_t = Default::default(); 

        let result = unsafe {
            ecall_get(self.enclave.as_ref().unwrap().geteid(),
                &mut retval,
                key.as_mut_ptr(),
                key.len(),
                nonce.as_mut_ptr(),
                nonce.len(),
                value.as_mut_ptr(),
                &mut len,
                &mut sig,)
        };
        unsafe {
            println!("len = {:?}", len);
            value.set_len(len);
        }
        value.shrink_to_fit();

        match result {
            sgx_status_t::SGX_SUCCESS => {},
            _ => {
                println!("[-] ECALL Enclave Failed {}!", result.as_str());
                return None;
            }
        };
        match retval {
            0 => None,
            1 => Some((value, sig)),
            _ => panic!("return number error"),
        }
    }
}


fn main() {

    let mut merk = CachedMerk::new();

    merk.destroy();
    
}
