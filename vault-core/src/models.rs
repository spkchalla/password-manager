use uuid::Uuid;
use serde::{Serialize, Deserialize};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry{
    pub id: Uuid,
    pub service: String,
    pub username: String,
    pub password: String,
}

impl VaultEntry{
    pub fn new(service: &str, username: &str, password: &str)-> Self{
        Self{
            id: Uuid::new_v4(),
            service: service.to_string(),
            username: username.to_string(),
            password: password.to_string(),
        }
    }
}


#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct Vault {
    pub entries: Vec<VaultEntry>,
}

impl Vault {
    pub fn new() -> Self{
        Self {entries: Vec::new()}
    }
    pub fn add_entry(&mut self, entry: VaultEntry){
        self.entries.push(entry);
    }

    pub fn list_entries(&self) -> &Vec<VaultEntry> {
        &self.entries
    }

    pub fn delete_entry(&mut self, id: Uuid)->bool{
        let before = self.entries.len();
        self.entries.retain(|e| e.id != id);
        before != self.entries.len()
    }

    pub fn update_entry(
        &mut self,
        id: Uuid,
        new_service: Option<&str>,
        new_username: Option<&str>,
        new_password: Option<&str>,
    ) -> bool{
        for entry in &mut self.entries{
            if entry.id == id{
                if let Some(s) = new_service{
                    entry.service = s.to_string();
                }
                if let Some(u) = new_username{
                    entry.username = u.to_string();
                }
                if let Some(p) = new_password {
                    entry.password = p.to_string();
                }
                return true;
            }
        }
        false
    }
}














