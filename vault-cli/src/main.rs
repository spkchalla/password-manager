use std::env;

fn main() {
   let args: Vec<String> = env::args().collect();

   if args.len()<2 {
       eprintln!("Usage: vault-cli <init|status>");
       return;
    }

    match args[1].as_str() {
        "init" => {
            use std::io::{self, Write};

            // Ask for master password setup
            print!("Set a master password: ");
            io::stdout().flush().unwrap();

            let mut master_password = String::new();
            io::stdin().read_line(&mut master_password).unwrap();
            let master_password = master_password.trim().to_string();

            // Call existing init_vault() to create vault file
            match vault_core::init_vault() {
                Ok(msg) => {
                    println!("{}", msg);
                    println!("Master password is set! (Remember it, you will need it for all operations)");
                },
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        "status" => {
            match vault_core::load_vault() {
                Ok(loaded) => {
                    println!("Vault loaded!");
                    println!("Salt: {:?}", loaded.salt);
                    println!("ciphertext length: {}", loaded.ciphertext.len());
                }
                Err(e) => eprintln!("Failed to load vault: {}", e),
            }
        }

        "add" =>{

        }

        "list" =>{
            use std::io::{self, Write};
            use vault_core::{load_vault, derive_key, load_vault_decrypted};

            // Ask for master password
            print!("Enter master password: ");
            io::stdout().flush().unwrap();

            let mut master_password = String::new();
            io::stdin().read_line(&mut master_password).unwrap();
            let master_password = master_password.trim();

            // Load vault to get salt
            let loaded = match load_vault() {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Failed to load vault: {}", e);
                    return;
                }
            };

            // Derive encryption key
            let key = derive_key(master_password, &loaded.salt);

            // Decrypt vault
            let vault = match load_vault_decrypted(&key){
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Decryption Failed: {}", e);
                    return;
                }
            };

            // Print all entries
            if vault.entries.is_empty() {
                println!("Vault is empty.");
            }else{
                for entry in vault.entries {
                    println!("--------------------");
                    println!("ID: {}", entry.id);
                    println!("Service: {}", entry.service);
                    println!("Username: {}", entry.username);
                    println!("Password: {}", entry.password);
                }
            }
        }

        "update" => {

        }

        "delete" => {

        }

        _ => eprintln!("Unknown Command!"),
    }
}
