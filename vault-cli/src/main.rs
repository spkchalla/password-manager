fn main() {
    match vault_core::init_vault() {
        Ok(msg) => println!("{}", msg),
        Err(e) => eprintln!("Failed to create vault: {}", e),
    }
}
