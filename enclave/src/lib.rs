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
#![crate_name = "merkenclave"]
#![crate_type = "staticlib"]

#![allow(non_snake_case)]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate lazy_static; 
use serde_derive::{Deserialize, Serialize};

use sgx_tcrypto::*;
use sgx_types::*;
use std::boxed::Box;
use std::cmp::min;
use std::collections::{btree_map::BTreeMap, HashMap};
use std::slice;
use std::sync::{atomic::Ordering, Arc, SgxRwLock as RwLock, SgxMutex as Mutex};
use std::time::Instant;
use std::untrusted::time::InstantEx;
use std::vec::Vec;

mod decoder;
use decoder::{verify_proof, };
mod hash;
use hash::{Hash, };

pub type KeyType = Vec<u8>;
pub type ValueType = Vec<u8>;

pub enum Op {
    Put(Vec<u8>),
    Delete,
}

struct InTee {
    rootHash: Option<Hash>,
    cache: HashMap<KeyType, ValueType>,
}

impl InTee {
    pub fn new() -> InTee {
        InTee {
            rootHash: None,
            cache: HashMap::new(),
        }
    }

    pub fn resetRootHash(&mut self, rootHash: Hash) {
        self.rootHash.replace(rootHash);
        self.cache.clear();
    }

    pub fn update(&mut self, key: &KeyType, op: Op, newRootHash: Hash, newProof: Vec<u8>) -> Result<(), &'static str> {
        // verify_proof()
        self.resetRootHash(newRootHash.clone());
        match op {
            Op::Delete => return Ok(()),
            Op::Put(v) => v,
        };

        let mut newValue = verify_proof(newProof.as_slice(), &[key.clone()], newRootHash).unwrap()[0].unwrap();
        self.cache.insert(*key, newValue);
        Ok(())
    }

    pub fn get(&self, rootHash: &Hash, key: &KeyType, nonce: &Vec<u8>) -> Option<(ValueType, sgx_ec256_signature_t)>{
        if rootHash != self.rootHash.as_ref().unwrap() {
            return None;
        }
        match self.cache.get(key) {
            Some(value) => Some((value.to_vec(), self.sign(value.to_vec(), nonce))),
            None => None,
        }
    }

    fn sign(&self, value: ValueType, nonce: &Vec<u8>) -> sgx_ec256_signature_t {
        let mut data = value;
        data.extend_from_slice(nonce);
        ecdsa_sign_slice(&data[..])
    }

}

lazy_static! {
    static ref INTEE: Arc<RwLock<InTee>> = Arc::new(RwLock::new(InTee::new()));
    static ref KEYPAIR: (sgx_ec256_private_t, sgx_ec256_public_t) = build_ecc_key();
}

#[no_mangle]
pub extern "C" fn ecall_get(key_ptr: *mut u8, key_len: usize,
                    nonce_ptr: *mut u8, nonce_len: usize,
                    value_ptr: *mut u8, value_len: &mut usize,
                    root_hash: &Hash, sig: &mut sgx_ec256_signature_t) -> u8
{
    let key = unsafe { slice::from_raw_parts(key_ptr, key_len) };
    let nonce = unsafe { slice::from_raw_parts(nonce_ptr, nonce_len) };
    let res = INTEE.read().unwrap().get(root_hash, &key.to_vec(), &nonce.to_vec());
    match res {
        Some((v, b)) => {
            *value_len = v.len();
            let mut value = unsafe { slice::from_raw_parts_mut(value_ptr, *value_len) }; 
            value.copy_from_slice(v.as_slice());
            *sig = b;
            1
        },
        None => 0,
    }
}

#[no_mangle]
pub extern "C" fn ecall_update(key_ptr: *mut u8, key_len: usize,
                        op: u8, value: *mut u8, new_root_hash: &Hash,
                        oproof_ptr: *mut u8, oproof_len: usize,
                        nproof_ptr: *mut u8, nproof_len: usize,) -> u8
{
    let key = unsafe { slice::from_raw_parts(key_ptr, key_len) };
    let oproof = unsafe { slice::from_raw_parts(oproof_ptr, oproof_len) };
    let nproof = unsafe { slice::from_raw_parts(nproof_ptr, nproof_len) };
    let value = unsafe { Box::from_raw(value as *mut ValueType) };
    let op = match op {
        0 => Op::Put(*value.clone()),  //check
        1 => Op::Delete,
        _ => panic!("invalid op num"),
    };
    Box::into_raw(value);
    let res = INTEE.write().unwrap().update(&key.to_vec(), op, new_root_hash.clone(), nproof.to_vec());
    match res {
        Ok(()) => 1,
        _ => 0,
    }
}

pub fn build_ecc_key() -> (sgx_ec256_private_t, sgx_ec256_public_t) {
    let ecc_handle = SgxEccHandle::new();
    let res = ecc_handle.open();
    match res {
        Err(e) => panic!("SgxEccHandle open error"),
        Ok(()) => {},
    };
    let res = ecc_handle.create_key_pair();
    let (priv_key, pub_key) = match res {
        Err(e) => panic!("SgxEccHandle create key pair error"),
        Ok(key) => key,
    };
    ecc_handle.close();
    (priv_key, pub_key) 
}

pub fn ecdsa_sign_slice<T>(data: &[T]) -> sgx_ec256_signature_t 
where T: Copy + sgx_types::marker::ContiguousMemory 
{
    let ecc_handle = SgxEccHandle::new();
    let res = ecc_handle.open();
    match res {
        Err(e) => panic!("SgxEccHandle open error"),
        Ok(()) => {},
    };
    let res = ecc_handle.ecdsa_sign_slice(data, &KEYPAIR.0);
    let sig = match res {
        Err(x) => panic!("SgxEccHandle sign error"),
        Ok(sig) => sig,
    };
    ecc_handle.close();
    sig
}