fn main() {
    let loaded = vault_core::load_vault().unwrap();

    println!("Salt: {:?}", loaded.salt);
    println!("cipher text length: {}", loaded.ciphertext.len());
}
