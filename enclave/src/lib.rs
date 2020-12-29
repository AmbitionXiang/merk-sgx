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

pub type Bytes = Vec<u8>;
pub type Hash = [u8; 20];
pub type Sig = [u8; 384];
pub type KeyType = Vec<u8>;
pub type ValueType = Vec<u8>;

/*
pub struct RsaPrivKey {
    key: sgx_rsa_key_t,
    mod_size: i32,
    exp_size: i32,
}

impl RsaPrivKey {
    pub fn new(
        mod_size: i32,
        exp_size: i32,
        e: &[u8],
        p: &[u8],
        q: &[u8],
        dmp1: &[u8],
        dmq1: &[u8],
        iqmp: &[u8]) -> Self
    {
        let mut key: sgx_rsa_key_t = std::ptr::null_mut(); 
        let ret = rsgx_create_rsa_priv_key(mod_size,
                                        exp_size,
                                        e,
                                        p,
                                        q,
                                        dmp1,
                                        dmq1,
                                        iqmp,
                                        key);
        match ret {
            sgx_status_t::SGX_SUCCESS => {
                RsaPrivKey {
                    key,
                    mod_size,
                    exp_size,
                }
            },
            _ => panic!("generate priv key error"),
        }
    }
}

pub struct RsaPubKey {
    key: sgx_rsa_key_t,
    mod_size: i32,
    exp_size: i32,
}

impl RsaPubKey {
    pub fn new( 
        mod_size: i32,
        exp_size: i32,
        n: &[u8],
        e: &[u8]) -> Self
    {
        let mut key: sgx_rsa_key_t = std::ptr::null_mut(); 
        let ret = rsgx_create_rsa_pub_key(mod_size,
                                        exp_size,
                                        n,
                                        e,
                                        key);
        match ret {
            sgx_status_t::SGX_SUCCESS => {
                RsaPubKey {
                    key,
                    mod_size,
                    exp_size,
                }
            },
            _ => panic!("generate pub key error"),
        }
    }
}
*/

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

    pub fn update(&mut self, key: &KeyType, op: Op, newRootHash: &Hash, oldProof: Vec<u8>, newProof: Vec<u8>) -> Result<(), &'static str> {
        Ok(())
    }

    fn verify() -> Result<bool, &'static str>{
        Ok(true)
    }

    pub fn get(&self, key: &KeyType, nonce: &Bytes) -> Option<(ValueType, Sig)>{
        match self.cache.get(key) {
            Some(value) => Some((value.to_vec(), self.sign(value.to_vec(), nonce).signature)),
            None => None
        }
    }

    fn sign(&self, value: ValueType, nonce: &Bytes) -> sgx_rsa3072_signature_t {
        let mut data = value;
        data.extend_from_slice(nonce);
        let result = rsgx_rsa3072_sign_msg(&data, &KEYPAIR.0);
        match result {
            Err(x) => panic!("sig error"),
            Ok(sig) => sig,
        }
    }

}

lazy_static! {
    static ref INTEE: Arc<RwLock<InTee>> = Arc::new(RwLock::new(InTee::new()));
    static ref KEYPAIR: (SgxRsaPrivKey, SgxRsaPubKey) = build_rsa_key();
}

#[no_mangle]
pub extern "C" fn ecall_get(key_ptr: *mut u8, key_len: usize,
                    nonce_ptr: *mut u8, nonce_len: usize,
                    value_ptr: *mut u8, value_len: &mut usize,
                    bytes: &mut Sig) -> u8
{
    let key = unsafe { slice::from_raw_parts(key_ptr, key_len) };
    let nonce = unsafe { slice::from_raw_parts(nonce_ptr, nonce_len) };
    let res = INTEE.get(key, nonce);
    match res {
        Some((v, b)) => {
            value_len = v.len();
            let mut value = unsafe { slice::from_raw_parts_mut(value_ptr, value_len) }; 
            value.copy_from_slice(v.as_slice());
            *bytes = b;
            1
        },
        None => 0,
    }
}

#[no_mangle]
pub extern "C" fn ecall_update(key_ptr: *mut u8, key_len: usize,
                        op: u8, value: *mut u8, newRootHash: &Hash,
                        oproof_ptr: *mut u8, oproof_len: usize,
                        nproof_ptr: *mut u8, nproof_len: usize,) -> u8
{
    let key = unsafe { slice::from_raw_parts(key_ptr, key_len) };
    let oproof = unsafe { slice::from_raw_parts(oproof_ptr, oproof_len) };
    let nproof = unsafe { slice::from_raw_parts(nproof_ptr, nproof_len) };
    let value = unsafe { Box::from_raw(value as *mut ValueType) };
    let op = match op {
        0 => Op::Put(value.clone()),  //check
        1 => Op::Delete,
    };
    Box::into_raw(value); 
    let res = INTEE.update(key, op, newRootHash, oproof.to_vec(), nproof.to_vec());
    match res {
        Ok(()) => 1,
        _ => 0,
    }
}

/*
pub fn build_rsa_key() -> (SgxPrivKey, RsaPubKey) {
    let mod_size: i32 = 256;
    let exp_size: i32 = 4;
    let mut n: Vec<u8> = vec![0_u8; mod_size as usize];
    let mut d: Vec<u8> = vec![0_u8; mod_size as usize];
    let mut e: Vec<u8> = vec![1, 0, 1, 0];
    let mut p: Vec<u8> = vec![0_u8; mod_size as usize / 2];
    let mut q: Vec<u8> = vec![0_u8; mod_size as usize / 2];
    let mut dmp1: Vec<u8> = vec![0_u8; mod_size as usize / 2];
    let mut dmq1: Vec<u8> = vec![0_u8; mod_size as usize / 2];
    let mut iqmp: Vec<u8> = vec![0_u8; mod_size as usize / 2];

    let result = rsgx_create_rsa_key_pair(mod_size,
                                          exp_size,
                                          n.as_mut_slice(),
                                          d.as_mut_slice(),
                                          e.as_mut_slice(),
                                          p.as_mut_slice(),
                                          q.as_mut_slice(),
                                          dmp1.as_mut_slice(),
                                          dmq1.as_mut_slice(),
                                          iqmp.as_mut_slice());

    match result {
        Err(x) => {
            return x;
        },
        Ok(()) => {},
    }

    let pub_key = RsaPubKey::new(mod_size,
                               exp_size,
                               n.as_slice(),
                               e.as_slice());

    let priv_key = RsaPrivKey.new(mod_size,
                                exp_size,
                                e.as_slice(),
                                p.as_slice(),
                                q.as_slice(),
                                dmp1.as_slice(),
                                dmq1.as_slice(),
                                iqmp.as_slice());

    (privkey, pubkey)
}
*/
pub fn build_rsa_key() -> (SgxRsaPrivKey, SgxRsaPubKey) {
    let mod_size: i32 = 256;
    let exp_size: i32 = 4;
    let mut n: Vec<u8> = vec![0_u8; mod_size as usize];
    let mut d: Vec<u8> = vec![0_u8; mod_size as usize];
    let mut e: Vec<u8> = vec![1, 0, 1, 0];
    let mut p: Vec<u8> = vec![0_u8; mod_size as usize / 2];
    let mut q: Vec<u8> = vec![0_u8; mod_size as usize / 2];
    let mut dmp1: Vec<u8> = vec![0_u8; mod_size as usize / 2];
    let mut dmq1: Vec<u8> = vec![0_u8; mod_size as usize / 2];
    let mut iqmp: Vec<u8> = vec![0_u8; mod_size as usize / 2];

    let result = rsgx_create_rsa_key_pair(mod_size,
                                        exp_size,
                                        n.as_mut_slice(),
                                        d.as_mut_slice(),
                                        e.as_mut_slice(),
                                        p.as_mut_slice(),
                                        q.as_mut_slice(),
                                        dmp1.as_mut_slice(),
                                        dmq1.as_mut_slice(),
                                        iqmp.as_mut_slice());

    match result {
        Err(x) => {
            return x;
        },
        Ok(()) => {},
    }

    let privkey = SgxRsaPrivKey::new();
    let pubkey = SgxRsaPubKey::new();

    let result = pubkey.create(mod_size,
                            exp_size,
                            n.as_slice(),
                            e.as_slice());
    match result {
        Err(x) => return x,
        Ok(()) => {},
    };

    let result = privkey.create(mod_size,
                                exp_size,
                                e.as_slice(),
                                p.as_slice(),
                                q.as_slice(),
                                dmp1.as_slice(),
                                dmq1.as_slice(),
                                iqmp.as_slice());
    match result {
        Err(x) => return x,
        Ok(()) => {},
    };
    (privkey, pubkey)
}