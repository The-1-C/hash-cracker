use std::time::{Instant};
use sha1::{Sha1, Digest};
use sha2::{Sha256};
use md5::{Md5};
use rand::{Rng, thread_rng};
use sled;

// --- SHARED HASHING LOGIC ---
fn hash_md5(input: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(input);
    hex::encode(hasher.finalize())
}

fn hash_sha1(input: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(input);
    hex::encode(hasher.finalize())
}

fn hash_sha256(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hex::encode(hasher.finalize())
}

// --- DB LOGIC ---

fn open_db(path: &str) -> sled::Db {
    sled::open(path).expect("Failed to open Sled DB")
}

fn main() {
    let db_path = "../rainbow_db"; // Sled directory
    println!("Opening Sled DB: {}", db_path);
    let db = open_db(db_path);
    
    // Try to recover previous count (slow) or just start count at 0 for session
    let initial_count = db.len();
    println!("DB currently has ~{} entries.", initial_count);

    let charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+}{\":?><-=[];',./";
    let charset_chars: Vec<char> = charset.chars().collect();
    let mut rng = thread_rng();
    
    let mut count = 0;
    let start_time = Instant::now();

    println!("Generating infinite random hashes. Press Ctrl+C to stop.");

    loop {
        // Generate random length (4 to 12)
        let len = rng.gen_range(4..=12);
        let random_string: String = (0..len)
            .map(|_| charset_chars[rng.gen_range(0..charset_chars.len())])
            .collect();

        // Compute hashes
        let h_md5 = hash_md5(&random_string);
        let h_sha1 = hash_sha1(&random_string);
        let h_sha256 = hash_sha256(&random_string);

        // Add to DB (check existence to be precise about "New" count)
        let mut added = false;
        
        // Sled contains_key
        if !db.contains_key(&h_md5).unwrap_or(false) { 
            let _ = db.insert(&h_md5, random_string.as_str()); 
            added = true; 
        }
        if !db.contains_key(&h_sha1).unwrap_or(false) { 
            let _ = db.insert(&h_sha1, random_string.as_str()); 
            added = true; 
        }
        if !db.contains_key(&h_sha256).unwrap_or(false) { 
            let _ = db.insert(&h_sha256, random_string.as_str()); 
            added = true; 
        }

        if added {
            count += 1;
        }
        
        // Update UI every 100 entries
        if count % 100 == 0 {
            print!("\rSession Generated: {} | Speed: {:.0} hash/s   ", count, count as f64 / start_time.elapsed().as_secs_f64().max(1.0));
        }
    }
}
