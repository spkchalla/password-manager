use std::fs::OpenOptions;
use std::fs::File;
use std::io::{Read, Write, Seek, Result};
pub mod models;

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


use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm::KeyInit;
use aes_gcm::aead::Aead;

pub fn encrypt_data(key: &[u8; 32], plaintext: &[u8])->(Vec<u8>, [u8; 12]) {
    let cipher = Aes256Gcm::new(key.into());

    // Generate random 12 byte nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let ciphertext = cipher.encrypt(nonce, plaintext)
        .expect("encryption failed");

    // Aes-Gcm embeds tag in ciphertext internally, so we can seperate if needed.
    let _tag = ciphertext[ciphertext.len()-16..].to_vec(); // this means the last 16 bytes are the tag

    (ciphertext, nonce_bytes)

}

pub fn decrypt_data(key: &[u8; 32], ciphertext: &[u8], nonce: &[u8; 12]) -> Vec<u8> {

    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(nonce);

    // we are assuming ciphertext includes tag in the end
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .expect("decryption failed");

    plaintext
}

use crate::models::{Vault};
use serde_json;

pub fn save_vault(vault: &Vault, key: &[u8; 32]) ->Result<()> {

    //turn vault into json bytes
    let plaintext = serde_json::to_vec(vault)?;

    //encrypt
    let (ciphertext, nonce_bytes) = encrypt_data(key, &plaintext);

    //open file
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open("vault.bin")?;

    //write salt already exists from init_vault, so move file ointer past salt
    file.seek(std::io::SeekFrom::Start(16))?;

    // write nonce + ciphertext

    file.write_all(&nonce_bytes)?;
    file.write_all(&ciphertext)?;

    Ok(())
}


pub fn load_vault_decrypted(key: &[u8; 32])-> Result<Vault>{
    let mut file = File::open("vault.bin")?;

    // read salt (16 bytes)
    let mut salt = [0u8;16];
    file.read_exact(&mut salt)?;

    // read nonce (12 bytes)
    let mut nonce_bytes = [0u8; 12];
    file.read_exact(&mut nonce_bytes)?;

    // read cipher text
    let mut ciphertext = Vec::new();
    file.read_to_end(&mut ciphertext)?;

    // decrypt
    let plaintext = decrypt_data(key, &ciphertext, &nonce_bytes);

    // parse JSON into Vault
    let vault: Vault = serde_json::from_slice(&plaintext)?;

    Ok(vault)
}







