import itertools

def generate_library(filename="wordlist.txt"):
    print(f"Generating common passwords into {filename}...")
    
    passwords = set()
    
    # 1. Add existing
    try:
        with open(filename, "r") as f:
            for line in f:
                passwords.add(line.strip())
    except FileNotFoundError:
        pass

    # 2. Add PINs (0000-9999)
    print("Adding 4-digit PINs...")
    for i in range(10000):
        passwords.add(f"{i:04d}")

    # 3. Add Years (1900-2030)
    print("Adding years...")
    for i in range(1900, 2031):
        passwords.add(str(i))

    # 4. Common patterns
    print("Adding common patterns...")
    common = [
        "password", "admin", "root", "guest", "user", "login",
        "123456", "12345", "12345678", "123456789", "qwerty",
        "football", "baseball", "dragon", "monkey", "letmeout"
    ]
    for c in common:
        passwords.add(c)

    # Write back
    with open(filename, "w") as f:
        for p in sorted(passwords):
            if p:
                f.write(p + "\n")
    
    print(f"Done! Library now has {len(passwords)} entries.")

if __name__ == "__main__":
    generate_library()
