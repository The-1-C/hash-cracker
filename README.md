# 🦀 Rust Hash Cracker & Rainbow Table Generator

A high-performance, multithreaded hash cracker written in Rust. It uses a persistent embedded database (Sled) to build massive Rainbow Tables for instant lookups, combined with smart hybrid attacks.

## 🚀 Features

-   **3-Stage Cracking Pipeline**:
    1.  **Instant Lookup**: Checks the Rainbow Table (Sled DB) in nanoseconds ($O(1)$).
    2.  **Hybrid Attack**: Checks dictionary words with appended numbers/symbols (`admin123`, `pass!`).
    3.  **Pure Brute Force**: Fallback to exhaustive search for short random passwords (1-7 chars).
-   **Smart Generator**: A background tool that generates millions of hashes/sec using your CPU cores.
    -   Uses "Smart Mutation" logic (Append digits, Combinator, Capitalization) based on your wordlist.
    -   Tags entries so you know how a password was found (e.g., `password123|smart_digit`).
-   **Persistent Storage**: Uses [Sled](https://github.com/spacejam/sled), a fast, crash-safe embedded database. No SQL server required.
-   **Auto-Learning**: Any new password cracked via brute-force is saved to the library.

## 🛠️ Prerequisites

1.  **Rust**: You need the Rust toolchain installed.
    -   Windows/Mac/Linux: Install from [rustup.rs](https://rustup.rs).

## 📥 Installation

Clone the repository and run the setup script:

```bash
git clone https://github.com/The-1-C/hash-cracker.git
cd hash-cracker
setup_project.bat
```

## 🎮 Usage

There are 3 main scripts to control everything:

### 1. `run_cracker.bat` (The Main Tool)
Runs the cracker.
-   **Imports** words from `wordlist.txt` into the database (and clears the file).
-   **Cracks** hashes listed in `hashes.txt`.
-   **Reports** which method found the password.

### 2. `generate_rainbow.bat` (The Builder)
Runs the infinite hash generator.
-   Uses **all CPU cores** to generate hashes at high speed.
-   Reads words from the DB to create "Smart" combinations (`admin_pass`, `monkey123`).
-   Fills your `rainbow_db` folder.
-   **Tip**: Leave this running in the background to build a billion-entry library.

### 3. `wordlist.txt` (The Input)
Paste new passwords or dictionaries here.
-   When you run `run_cracker.bat`, it "ingests" these words into the database permanent storage.
-   The file is then automatically cleared.

## 📂 File Structure

-   `hashes.txt`: List of target hashes to crack (MD5, SHA1, SHA256 supported).
-   `wordlist.txt`: Input queue for new dictionary words.
-   `rainbow_db/`: The binary database folder (Do not delete unless you want to wipe everything).
-   `rust_cracker/`: Source code.

## ⚡ Performance Tips

-   **1 Billion+ Entries**: Sled handles this fine, but it will take disk space (~50GB+).
-   **Brute Force Depth**: Currently set to **7 characters** max. Increasing this to 8+ will drastically increase crack time (exponential growth).
-   **Combinator Attacks**: The Cracker does *not* run $O(N^2)$ combinator attacks at runtime (too slow). Instead, the **Generator** pre-computes these into the DB over time.

## 📜 License

MIT License
