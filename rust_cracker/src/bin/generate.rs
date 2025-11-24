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
    sled::Config::default()
        .path(path)
        .cache_capacity(1024 * 1024 * 1024) // 1GB Cache
        .mode(sled::Mode::HighThroughput)   // Optimize for speed
        .open()
        .expect("Failed to open Sled DB")
}

fn load_words_from_db(db: &sled::Db) -> Vec<String> {
    let mut words = Vec::new();
    if let Ok(tree) = db.open_tree("words") {
        for item in tree.iter() {
            if let Ok((key, _)) = item {
                if let Ok(w) = String::from_utf8(key.to_vec()) {
                    words.push(w);
                }
            }
        }
    }
    words
}

fn main() {
    let db_path = "../rainbow_db"; // Sled directory
    println!("Opening Sled DB: {}", db_path);
    let db = open_db(db_path);
    
    let words = load_words_from_db(&db);
    println!("Loaded {} base words for smart generation.", words.len());
    if words.is_empty() {
        println!("Warning: No words found in DB. Generator will revert to pure random mode.");
    }
    
    // Try to recover previous count (slow) or just start count at 0 for session
    let initial_count = db.len();
    println!("DB currently has ~{} entries.", initial_count);

    let charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+}{\":?><-=[];',./";
    let charset_chars: Vec<char> = charset.chars().collect();
    let mut rng = thread_rng();
    
    let mut count = 0;
    let start_time = Instant::now();

    println!("Generating infinite SMART hashes. Press Ctrl+C to stop.");

    loop {
        let candidate: String;
        
        // Decide strategy (Weighted probability)
        let strategy = rng.gen_range(0..100);
        
        if !words.is_empty() && strategy < 70 {
            // 70% Chance: Smart Mutation using Wordlist
            let word = &words[rng.gen_range(0..words.len())];
            let sub_strat = rng.gen_range(0..4);
            
            if sub_strat == 0 {
                // Append Digits (e.g. password123)
                candidate = format!("{}{}", word, rng.gen_range(0..9999));
            } else if sub_strat == 1 {
                // Append Symbol (e.g. password!)
                let sym = charset_chars[rng.gen_range(52..charset_chars.len())]; // roughly symbols area
                candidate = format!("{}{}", word, sym);
            } else if sub_strat == 2 && words.len() > 1 {
                // Combinator (e.g. adminpassword)
                let word2 = &words[rng.gen_range(0..words.len())];
                candidate = format!("{}{}", word, word2);
            } else {
                 // Capitalize + Digit
                 let mut chars = word.chars();
                 if let Some(first) = chars.next() {
                     let cap_word = first.to_uppercase().collect::<String>() + chars.as_str();
                     candidate = format!("{}{}", cap_word, rng.gen_range(0..999));
                 } else {
                     candidate = word.to_string();
                 }
            }
        } else {
            // 30% Chance (or if empty): Pure Random (Fallback)
            let len = rng.gen_range(4..=12);
            candidate = (0..len)
                .map(|_| charset_chars[rng.gen_range(0..charset_chars.len())])
                .collect();
        }

        // Compute hashes
        let h_md5 = hash_md5(&candidate);
        let h_sha1 = hash_sha1(&candidate);
        let h_sha256 = hash_sha256(&candidate);

        // Add to DB
        let mut added = false;
        
        if !db.contains_key(&h_md5).unwrap_or(false) { 
            let _ = db.insert(&h_md5, candidate.as_str()); 
            added = true; 
        }
        if !db.contains_key(&h_sha1).unwrap_or(false) { 
            let _ = db.insert(&h_sha1, candidate.as_str()); 
            added = true; 
        }
        if !db.contains_key(&h_sha256).unwrap_or(false) { 
            let _ = db.insert(&h_sha256, candidate.as_str()); 
            added = true; 
        }

        if added {
            count += 1;
        }
        
        if count % 100 == 0 {
            print!("\rSession Generated: {} | Speed: {:.0} hash/s   ", count, count as f64 / start_time.elapsed().as_secs_f64().max(1.0));
        }
    }
}
