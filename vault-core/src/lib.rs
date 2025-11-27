use std::fs::File;
use std::io::Result;

pub fn hello_core() -> &'static str {
    "vault-core is working!"
}

pub fn init_vault() -> Result<String> {
    // To define the path
    let path = "vault.bin";

    // To create a file (if it already exists, it truncates and create a new one)
    File::create(path)?;

    Ok(format!("Vault created at {}", path))
}
