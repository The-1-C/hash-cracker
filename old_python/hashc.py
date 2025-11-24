import hashlib
import itertools
import threading
import queue
import time

# ------------------------------
# AUTO-DETECT HASH TYPE
# ------------------------------
def detect_hash_type(hash_str):
    length = len(hash_str)

    if length == 32:
        return "md5"
    elif length == 40:
        return "sha1"
    elif length == 64:
        return "sha256"
    else:
        return None

# ------------------------------
# HASH FUNCTION (built-in)
# ------------------------------
def hash_password(alg, pwd):
    pwd = pwd.encode()
    if alg == "md5":
        return hashlib.md5(pwd).hexdigest()
    elif alg == "sha1":
        return hashlib.sha1(pwd).hexdigest()
    elif alg == "sha256":
        return hashlib.sha256(pwd).hexdigest()
    else:
        raise ValueError("Unknown algorithm")

# ------------------------------
# LOAD HASHES FROM FILE
# file should contain one hash per line
# ------------------------------
def load_hashes(filename):
    with open(filename, "r") as f:
        return [line.strip() for line in f.readlines() if line.strip()]

# ------------------------------
# MASK SYSTEM:
# ?l = lowercase
# ?u = uppercase
# ?d = digits
# ?s = symbols
# ------------------------------
mask_sets = {
    "?l": "abcdefghijklmnopqrstuvwxyz",
    "?u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "?d": "0123456789",
    "?s": "!@#$%^&*()-_=+[]{};:'\",.<>/?\\|"
}

def expand_mask(mask):
    parts = []
    i = 0
    while i < len(mask):
        if mask[i] == "?" and i+1 < len(mask):
            token = mask[i:i+2]
            if token in mask_sets:
                parts.append(mask_sets[token])
                i += 2
            else:
                raise ValueError("Unknown mask token: " + token)
        else:
            parts.append(mask[i])
            i += 1
    return parts

# ------------------------------
# WORDLIST/LIBRARY CHECK
# ------------------------------
def check_wordlist(alg, target_hash, wordlist_file="wordlist.txt"):
    try:
        with open(wordlist_file, "r") as f:
            for line in f:
                word = line.strip()
                if not word:
                    continue
                if hash_password(alg, word) == target_hash:
                    return word
    except FileNotFoundError:
        print(f"Warning: {wordlist_file} not found. Skipping dictionary attack.")
    return None

# ------------------------------
# MULTITHREADED BRUTE FORCE
# ------------------------------
def worker(task_queue, found, alg, target_hash):
    while not found["value"]:
        try:
            candidate = task_queue.get_nowait()
        except queue.Empty:
            return

        if hash_password(alg, candidate) == target_hash:
            found["value"] = candidate
            return

        task_queue.task_done()

def start_multithread_bruteforce(alg, target_hash, mask, threads=8):
    alphabet_list = expand_mask(mask)
    task_queue = queue.Queue()
    found = {"value": None}

    # Fill task queue
    for combo in itertools.product(*alphabet_list):
        task_queue.put("".join(combo))

    # Start threads
    ths = []
    for _ in range(threads):
        t = threading.Thread(target=worker, args=(task_queue, found, alg, target_hash))
        t.start()
        ths.append(t)

    # Wait for all threads
    for t in ths:
        t.join()

    return found["value"]

# ------------------------------
# MAIN DEMO
# ------------------------------
if __name__ == "__main__":
    print("Loading hashes from file: hashes.txt")
    hashes = load_hashes("hashes.txt")

    for h in hashes:
        print("\nTarget:", h)

        alg = detect_hash_type(h)
        if not alg:
            print("Cannot detect algorithm for:", h)
            continue

        print("Detected algorithm:", alg)

        # 1. Check Wordlist (Library) first
        print("Checking wordlist...")
        found = check_wordlist(alg, h)
        if found:
             print(f"FOUND IN LIBRARY: {found}")
             print("Time elapsed: 0.0s (Library hit)")
             continue

        # 2. Brute Force
        # Try a sequence of common masks
        masks_to_try = [
            # Digits 1-6
            "?d", "?d?d", "?d?d?d", "?d?d?d?d", "?d?d?d?d?d", "?d?d?d?d?d?d",
            # Lowercase 1-5
            "?l", "?l?l", "?l?l?l", "?l?l?l?l", "?l?l?l?l?l"
        ]

        print(f"Starting incremental brute force ({len(masks_to_try)} patterns)...")
        start = time.time()
        
        result = None
        for mask in masks_to_try:
            print(f"Trying mask: {mask} ...", end="\r")
            result = start_multithread_bruteforce(alg, h, mask, threads=8)
            if result:
                print(f"Trying mask: {mask} -> FOUND!")
                break
        
        if not result:
            print("\nAll masks exhausted.")

        end = time.time()

        if result:
            print("FOUND PASSWORD:", result)
            # Add to wordlist if not already there
            try:
                # check existence first to avoid duplicates (simple check)
                with open("wordlist.txt", "r+") as f:
                    content = f.read()
                    if result not in content:
                        f.write("\n" + result)
                        print(f"Saved '{result}' to wordlist.txt for future use.")
            except Exception as e:
                print("Could not save to wordlist:", e)
        else:
            print("Password NOT found.")

        print("Time elapsed:", round(end - start, 4), "seconds")
