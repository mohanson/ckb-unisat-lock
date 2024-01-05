#![no_std]
#![no_main]

use ckb_auth_rs::{
    ckb_auth, generate_sighash_all, AuthAlgorithmIdType, CkbAuthType, CkbEntryType,
    EntryCategoryType,
};
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, core::ScriptHashType, prelude::*},
    default_alloc,
    high_level::{load_script, load_witness_args},
};

ckb_std::entry!(main);
default_alloc!();

const AUTH_CODE_HASH: &str = "55ef3361a3843cc82d91ad56a1fd125a8228933fa7ac2d52b861c80f224f2a79";
const AUTH_HASH_TYPE: ScriptHashType = ScriptHashType::Data1;

fn main() -> i8 {
    let message = generate_sighash_all().unwrap();
    let signature = {
        let witness_args = load_witness_args(0, Source::GroupInput).unwrap();
        let witness = witness_args.lock().to_opt().unwrap().raw_data();
        witness.to_vec()
    };
    let script_args: [u8; 21] = {
        let script = load_script().unwrap();
        let args: Bytes = script.args().unpack();
        args.to_vec().try_into().unwrap()
    };
    let id = CkbAuthType {
        algorithm_id: AuthAlgorithmIdType::try_from(script_args[0]).unwrap(),
        pubkey_hash: script_args[1..21].try_into().unwrap(),
    };
    let code_hash: [u8; 32] = {
        let code_hash = hex::decode(AUTH_CODE_HASH).unwrap();
        code_hash.try_into().unwrap()
    };
    let entry = CkbEntryType {
        code_hash: code_hash,
        hash_type: AUTH_HASH_TYPE,
        entry_category: EntryCategoryType::Exec,
    };
    ckb_auth(&entry, &id, &signature, &message).unwrap();
    return 0;
}
