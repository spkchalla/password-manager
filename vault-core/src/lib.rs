use std::fs::OpenOptions;
use std::fs::File;
use std::io::{Read, Write, Result};

use rand::rngs::OsRng;
use rand::RngCore;

const SALT_LEN: usize = 16;


pub fn hello_core() -> &'static str {
    "vault-core is working!"
}

pub fn init_vault() -> Result<String> {
    // To define the path
    let path = "vault.bin";

    // This will open file for writing and create if not exists.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true) // This will throw an error if it already exists
        .open(path)?;

    // Generating salt
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    // Write salt as first bytes of the file
    file.write_all(&salt)?;

    Ok(format!("Vault created at {}", path))
}

pub struct LoadedVault {
    pub salt: [u8; 16],
    pub ciphertext: Vec<u8>,
}

pub fn load_vault() -> Result<LoadedVault> {
    let mut file = File::open("vault.bin")?;

    // Read salt
    let mut salt = [0u8; 16];
    file.read_exact(&mut salt)?;

    // Read encrypted bytes

    let mut ciphertext = Vec::new();
    file.read_to_end(&mut ciphertext)?;

    Ok(LoadedVault {salt, ciphertext})
}


use argon2::{Argon2};
use argon2::password_hash::{SaltString, PasswordHasher as _};

pub fn derive_key(master_password: &str, salt:&[u8]) -> [u8; 32]{
    let argon2 = Argon2::default();

    // Convert raw bytes -> saltstring(argon2 requirement)
    let salt_str = SaltString::encode_b64(salt).expect("valid salt");

    // Hash password using argon2id
    let hash = argon2
        .hash_password(master_password.as_bytes(), &salt_str)
        .expect("argon2 hashing failed");

    // Extract raw bytes from argon2 output

    let hash_value = hash.hash.expect("hash is missing");
    let hash_bytes = hash_value.as_bytes();
    // Convert into fixed 32 byte array

    let mut key = [0u8; 32];
    key.copy_from_slice(hash_bytes);

    key
}















