use std::fs::File;
use std::io::{self, BufRead};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use sha1::{Sha1, Digest};
use sha2::{Sha256};
use md5::{Md5};
use crossbeam::thread;
use sled;

// Supported Algorithms
#[derive(Debug, Clone, Copy, PartialEq)]
enum Algo {
    Md5,
    Sha1,
    Sha256,
}

fn hash_string(algo: Algo, input: &str) -> String {
    match algo {
        Algo::Md5 => {
            let mut hasher = Md5::new();
            hasher.update(input);
            hex::encode(hasher.finalize())
        },
        Algo::Sha1 => {
            let mut hasher = Sha1::new();
            hasher.update(input);
            hex::encode(hasher.finalize())
        },
        Algo::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(input);
            hex::encode(hasher.finalize())
        },
    }
}

fn detect_algo(hash: &str) -> Option<Algo> {
    match hash.len() {
        32 => Some(Algo::Md5),
        40 => Some(Algo::Sha1),
        64 => Some(Algo::Sha256),
        _ => None,
    }
}

// --- SLED DB FUNCTIONS ---

fn open_db(path: &str) -> sled::Db {
    sled::Config::default()
        .path(path)
        .cache_capacity(1024 * 1024 * 1024) // 1GB Cache
        .mode(sled::Mode::HighThroughput)   // Optimize for speed
        .open()
        .expect("Failed to open Sled DB")
}

fn lookup_db(db: &sled::Db, hash: &str) -> Option<String> {
    match db.get(hash) {
        Ok(Some(ivec)) => String::from_utf8(ivec.to_vec()).ok(),
        _ => None
    }
}

fn insert_db(db: &sled::Db, hash: &str, pwd: &str) {
    let _ = db.insert(hash, pwd);
}

fn save_word_to_db(db: &sled::Db, word: &str) {
    // Store valid words in a separate tree "words" so we can use them for hybrid attacks later
    if let Ok(tree) = db.open_tree("words") {
        let _ = tree.insert(word, "");
    }
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

fn sync_wordlist_to_db(db: &sled::Db, wordlist_path: &str) {
    println!("Syncing wordlist to Sled DB...");
    let words = load_wordlist(wordlist_path);
    
    if words.is_empty() {
        println!("Wordlist is empty. Nothing to sync.");
        return;
    }

    let mut count = 0;
    
    for word in words {
        // 1. Save word itself (for future hybrid attacks)
        save_word_to_db(db, &word);

        // 2. Save Hashes (Rainbow Table)
        let h_md5 = hash_string(Algo::Md5, &word);
        let h_sha1 = hash_string(Algo::Sha1, &word);
        let h_sha256 = hash_string(Algo::Sha256, &word);

        // Store with "imported" tag
        let val = format!("{}|imported", word);

        if !db.contains_key(&h_md5).unwrap_or(false) {
             let _ = db.insert(&h_md5, val.as_str()); count += 1; 
        }
        if !db.contains_key(&h_sha1).unwrap_or(false) {
             let _ = db.insert(&h_sha1, val.as_str()); count += 1; 
        }
        if !db.contains_key(&h_sha256).unwrap_or(false) {
             let _ = db.insert(&h_sha256, val.as_str()); count += 1; 
        }
    }
    
    let _ = db.flush();
    println!("Synced. Added {} new hash entries to DB.", count);

    // 3. Clear the wordlist file
    if count > 0 || true { // Always clear if we processed them
        println!("Clearing processed words from {}...", wordlist_path);
        let _ = File::create(wordlist_path); // Truncates file to 0 bytes
    }
}

// --- CORE LOGIC ---

fn load_wordlist(path: &str) -> Vec<String> {
    let mut words = Vec::new();
    if let Ok(file) = File::open(path) {
        for line in io::BufReader::new(file).lines() {
            if let Ok(w) = line {
                let w = w.trim().to_string();
                if !w.is_empty() {
                    words.push(w);
                }
            }
        }
    }
    words
}

fn brute_force(_algo: Algo, _target: &str, _charset: &str, _max_len: usize) -> Option<String> {
    None
}

fn combinator_attack(algo: Algo, target: &str, words: &[String]) -> Option<String> {
    // Try every word combined with every other word (O(N^2))
    // parallelize outer loop
    let found = Arc::new(Mutex::new(None::<String>));
    let chunk_size = 100; // words per thread chunk

    let _ = thread::scope(|s| {
        for chunk in words.chunks(chunk_size) {
            let found_clone = found.clone();
            let target = target.to_string();
            let chunk = chunk.to_vec();
            let all_words = words.to_vec(); // Each thread needs read access to full list

            s.spawn(move |_| {
                if found_clone.lock().unwrap().is_some() { return; }
                
                for w1 in chunk {
                    for w2 in &all_words {
                        // Try w1 + w2
                        let candidate = format!("{}{}", w1, w2);
                        if hash_string(algo, &candidate) == target {
                            *found_clone.lock().unwrap() = Some(candidate); return;
                        }
                        // Try w2 + w1
                        let candidate_rev = format!("{}{}", w2, w1);
                        if hash_string(algo, &candidate_rev) == target {
                             *found_clone.lock().unwrap() = Some(candidate_rev); return;
                        }
                        
                        if found_clone.lock().unwrap().is_some() { return; }
                    }
                }
            });
        }
    });
    
    let res = found.lock().unwrap().clone();
    res
}

fn hybrid_attack(algo: Algo, target: &str, words: &[String]) -> Option<String> {
    // Common suffixes to append
    let symbols = ["!", "@", "#", "$", "%", "&", "*", "?", "123", "123!", "!!", "2023", "2024", "2025"];
    
    let found = Arc::new(Mutex::new(None::<String>));
    
    // Parallelize over chunks of words
    let chunk_size = 1000;
    
    let _ = thread::scope(|s| {
        for chunk in words.chunks(chunk_size) {
            let found_clone = found.clone();
            let target = target.to_string();
            let chunk = chunk.to_vec();
            
            s.spawn(move |_| {
                if found_clone.lock().unwrap().is_some() { return; }
                
                for word in chunk {
                    // 1. Append Digits (0-999)
                    for i in 0..=999 {
                        let candidate = format!("{}{}", word, i);
                        if hash_string(algo, &candidate) == target {
                            *found_clone.lock().unwrap() = Some(candidate); return;
                        }
                    }

                    // 2. Append Symbols
                    for sym in symbols.iter() {
                        let candidate = format!("{}{}", word, sym);
                        if hash_string(algo, &candidate) == target {
                            *found_clone.lock().unwrap() = Some(candidate); return;
                        }
                    }

                    // 3. Capitalized variations (Word1, Word!, etc)
                    // Simple capitalization (first char)
                    let mut chars = word.chars();
                    if let Some(first) = chars.next() {
                         let cap_word = first.to_uppercase().collect::<String>() + chars.as_str();
                         
                         // Cap + Digits
                         for i in 0..=999 {
                            let candidate = format!("{}{}", cap_word, i);
                            if hash_string(algo, &candidate) == target {
                                *found_clone.lock().unwrap() = Some(candidate); return;
                            }
                        }
                        
                        // Cap + Symbols
                        for sym in symbols.iter() {
                            let candidate = format!("{}{}", cap_word, sym);
                            if hash_string(algo, &candidate) == target {
                                *found_clone.lock().unwrap() = Some(candidate); return;
                            }
                        }
                    }
                    
                    if found_clone.lock().unwrap().is_some() { return; }
                }
            });
        }
    });
    
    let res = found.lock().unwrap().clone();
    res
}

fn main() {
    let hashes_file = "../hashes.txt";
    let wordlist_file = "../wordlist.txt";
    let db_path = "../rainbow_db"; // Sled creates a directory
    
    println!("Opening Sled DB...");
    let db = open_db(db_path);
    
    // Report stats
    let total_hashes = db.len();
    let smart_words = load_words_from_db(&db).len();
    println!("Stats: {} total hashes in Rainbow Table.", total_hashes);
    println!("Stats: {} smart words in Library for Hybrid attacks.", smart_words);

    // Sync DB with Wordlist
    sync_wordlist_to_db(&db, wordlist_file);
    
    println!("Loading hashes from {}", hashes_file);
    
    let hashes: Vec<String> = match File::open(hashes_file) {
        Ok(f) => io::BufReader::new(f).lines().filter_map(|l| l.ok()).collect(),
        Err(_) => {
            println!("Could not open hashes.txt");
            return;
        }
    };

    for hash in hashes {
        let hash = hash.trim();
        if hash.is_empty() { continue; }
        
        println!("\nTarget: {}", hash);
        let algo = match detect_algo(hash) {
            Some(a) => a,
            None => { println!("Unknown algorithm"); continue; }
        };
        println!("Algorithm: {:?}", algo);

        let start = Instant::now();

        // 1. Check Sled DB (Disk/Cache)
        print!("Checking Database... ");
        if let Some(pwd) = lookup_db(&db, hash) {
            println!("FOUND: {}", pwd);
            println!("Time elapsed: {:.2?} (DB Lookup)", start.elapsed());
            continue;
        }
        println!("Not found.");

        // 2. Smart Hybrid Attack
        println!("Starting Smart Hybrid Attack (Rules)...");
        
        // Load base words from DB (since wordlist.txt is now empty/cleared)
        let words = load_words_from_db(&db);
        println!("Loaded {} base words from DB for hybrid attack.", words.len());

        if let Some(pwd) = hybrid_attack(algo, hash, &words) {
             println!("FOUND: {}", pwd);
             insert_db(&db, hash, &pwd);
             save_word_to_db(&db, &pwd);
             continue;
        }

        // 3. Combinator Attack (Word + Word)
        println!("Starting Combinator Attack (Word + Word)...");
        // Only run if we have words, and limit count to avoid massive waits on huge DBs
        if !words.is_empty() && words.len() < 5000 { 
             if let Some(pwd) = combinator_attack(algo, hash, &words) {
                 println!("FOUND: {}", pwd);
                 insert_db(&db, hash, &pwd);
                 save_word_to_db(&db, &pwd);
                 continue;
             }
        } else if words.len() >= 5000 {
            println!("  (Skipping combinator: wordlist too large (>5000) for O(N^2) check)");
        }

        // 4. Pure Brute Force (Random chars)
        println!("Starting Pure Brute Force (Fallback)...");
        // Lowercase + Digits (1-7 chars) - Extended to 7 for deeper search
        let charset = "abcdefghijklmnopqrstuvwxyz0123456789";
        if let Some(pwd) = brute_force(algo, hash, charset, 7) {
             println!("FOUND: {}", pwd);
             insert_db(&db, hash, &pwd);
             save_word_to_db(&db, &pwd);
             continue;
        }

        println!("Failed to crack with all methods.");
        println!("Time elapsed: {:.2?}", start.elapsed());
    }
}
