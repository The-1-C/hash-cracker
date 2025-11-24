use std::fs;
use std::time::{Instant};
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use std::thread;
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
    let db_path = "../rainbow_db";
    println!("Opening Sled DB: {}", db_path);
    let db = open_db(db_path);
    
    let words = load_words_from_db(&db);
    println!("Loaded {} base words for smart generation.", words.len());
    if words.is_empty() {
        println!("Warning: No words found in DB. Generator will revert to pure random mode.");
    }
    
    let initial_count = db.len();
    println!("DB currently has ~{} entries.", initial_count);

    let charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+}{\":?><-=[];',./";
    
    // Shared counter for stats
    let session_count = Arc::new(AtomicUsize::new(0));
    let start_time = Instant::now();

    println!("Generating infinite SMART hashes on ALL CORES. Press Ctrl+C to stop.");

    // Detect CPU cores
    let num_threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    println!("Spawning {} worker threads...", num_threads);

    let words_arc = Arc::new(words);
    let charset_arc = Arc::new(charset.to_string());

    let mut handles = vec![];

    for _ in 0..num_threads {
        let db_clone = db.clone();
        let words_clone = words_arc.clone();
        let charset_clone = charset_arc.clone();
        let counter_clone = session_count.clone();

        let handle = thread::spawn(move || {
            let charset_chars: Vec<char> = charset_clone.chars().collect();
            let mut rng = thread_rng();
            
            loop {
                let candidate: String;
                let tag: &str;
                
                // Decide strategy (Weighted probability)
                // 80% Smart (if words exist), 20% Pure Random
                let strategy = rng.gen_range(0..100);
                
                if !words_clone.is_empty() && strategy < 80 {
                    // SMART MODE
                    let word = &words_clone[rng.gen_range(0..words_clone.len())];
                    let sub_strat = rng.gen_range(0..100);
                    
                    if sub_strat < 40 {
                        // 40% Chance: Digits (password123)
                        candidate = format!("{}{}", word, rng.gen_range(0..9999));
                        tag = "smart_digit";
                    } else if sub_strat < 60 {
                        // 20% Chance: Symbol (password!)
                        let sym = charset_chars[rng.gen_range(52..charset_chars.len())]; 
                        candidate = format!("{}{}", word, sym);
                        tag = "smart_symbol";
                    } else if sub_strat < 90 && words_clone.len() > 1 {
                        // 30% Chance: Combinator (adminpassword) - INCREASED PRIORITY
                        let word2 = &words_clone[rng.gen_range(0..words_clone.len())];
                        // Random separator sometimes
                        if rng.gen_bool(0.2) {
                            candidate = format!("{}_{}", word, word2);
                        } else {
                             candidate = format!("{}{}", word, word2);
                        }
                        tag = "combinator";
                    } else {
                         // 10% Chance: Capitalize + Digit
                         let mut chars = word.chars();
                         if let Some(first) = chars.next() {
                             let cap_word = first.to_uppercase().collect::<String>() + chars.as_str();
                             candidate = format!("{}{}", cap_word, rng.gen_range(0..999));
                         } else {
                             candidate = word.to_string();
                         }
                         tag = "smart_cap";
                    }
                } else {
                    // PURE RANDOM MODE
                    let len = rng.gen_range(4..=12);
                    candidate = (0..len)
                        .map(|_| charset_chars[rng.gen_range(0..charset_chars.len())])
                        .collect();
                    tag = "random";
                }

                // Compute hashes
                let h_md5 = hash_md5(&candidate);
                let h_sha1 = hash_sha1(&candidate);
                let h_sha256 = hash_sha256(&candidate);

                // Store with metadata tag
                let value_with_tag = format!("{}|{}", candidate, tag);

                // Add to DB
                let mut added = false;
                
                if !db_clone.contains_key(&h_md5).unwrap_or(false) { 
                    let _ = db_clone.insert(&h_md5, value_with_tag.as_str()); 
                    added = true; 
                }
                if !db_clone.contains_key(&h_sha1).unwrap_or(false) { 
                    let _ = db_clone.insert(&h_sha1, value_with_tag.as_str()); 
                    added = true; 
                }
                if !db_clone.contains_key(&h_sha256).unwrap_or(false) { 
                    let _ = db_clone.insert(&h_sha256, value_with_tag.as_str()); 
                    added = true; 
                }

                if added {
                    counter_clone.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        handles.push(handle);
    }

    // Monitor Thread
    loop {
        thread::sleep(std::time::Duration::from_millis(500));
        let count = session_count.load(Ordering::Relaxed);
        let elapsed = start_time.elapsed().as_secs_f64().max(1.0);
        print!("\rSession Generated: {} | Speed: {:.0} hash/s   ", count, count as f64 / elapsed);
    }
}
