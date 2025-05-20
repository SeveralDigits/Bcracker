import sqlite3
import bcrypt
import sys
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

def load_users(db_path):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT username, password_hash FROM users")
    users = c.fetchall()
    conn.close()
    return users

def verify_password(hash_bytes, password):
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hash_bytes)
    except:
        return False

def wordlist_crack(hash_bytes, wordlist_path, max_workers=8):
    print(f"Starting wordlist cracking with {wordlist_path}...")
    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
        passwords = [line.strip() for line in f if line.strip()]
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(verify_password, hash_bytes, pw): pw for pw in passwords}
        for future in as_completed(futures):
            if future.result():
                return futures[future]
    return None

def numeric_bruteforce(hash_bytes, max_workers=8):
    print("Starting 4-digit numeric brute force cracking...")
    batch_size = 1000
    def verify_batch(start):
        for i in range(start, min(start + batch_size, 10000)):
            pw = f"{i:04d}"
            if verify_password(hash_bytes, pw):
                return pw
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(verify_batch, i) for i in range(0, 10000, batch_size)]
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                return result
    return None

def charset_bruteforce(hash_bytes, charset="abcdefghijklmnopqrstuvwxyz0123456789", max_length=4, max_workers=8):
    print(f"Starting charset brute force cracking (max length {max_length})...")
    from itertools import product

    def verify_batch(pw_batch):
        for pw in pw_batch:
            if verify_password(hash_bytes, pw):
                return pw
        return None

    batch_size = 10000
    all_pwds = []
    for length in range(1, max_length + 1):
        for pw_tuple in product(charset, repeat=length):
            all_pwds.append(''.join(pw_tuple))
            if len(all_pwds) == batch_size:
                yield all_pwds
                all_pwds = []
    if all_pwds:
        yield all_pwds

def charset_bruteforce_runner(hash_bytes, charset="abcdefghijklmnopqrstuvwxyz0123456789", max_length=4, max_workers=8):
    from concurrent.futures import ThreadPoolExecutor, as_completed

    gen = charset_bruteforce(hash_bytes, charset, max_length, max_workers)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for batch in gen:
            futures = {executor.submit(verify_password, hash_bytes, pw): pw for pw in batch}
            for future in as_completed(futures):
                if future.result():
                    return futures[future]
    return None

def crack_password(hash_bytes, method, wordlist=None, max_workers=8):
    if method == 1:  # wordlist
        if not wordlist:
            print("No wordlist selected, cannot perform wordlist cracking.")
            return None
        return wordlist_crack(hash_bytes, wordlist, max_workers)
    elif method == 2:  # 4-digit numeric brute force
        return numeric_bruteforce(hash_bytes, max_workers)
    elif method == 3:  # charset brute force
        return charset_bruteforce_runner(hash_bytes, max_workers=max_workers)
    elif method == 4:  # combined: try wordlist -> numeric -> charset
        if wordlist:
            result = wordlist_crack(hash_bytes, wordlist, max_workers)
            if result:
                return result
        result = numeric_bruteforce(hash_bytes, max_workers)
        if result:
            return result
        return charset_bruteforce_runner(hash_bytes, max_workers=max_workers)
    else:
        print("Invalid cracking method.")
        return None

def group_users_by_hash(users):
    groups = {}
    for username, hash_str in users:
        groups.setdefault(hash_str, []).append(username)
    return groups

def select_from_list(prompt, options):
    print(prompt)
    for idx, option in enumerate(options, 1):
        print(f"{idx}) {option}")
    while True:
        choice = input("Select number: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            return int(choice)
        print("Invalid choice, please try again.")

def select_wordlist():
    wordlists = [f for f in os.listdir('.') if f.endswith('.txt')]
    if not wordlists:
        print("No wordlist files found in current directory.")
        return None
    choice = select_from_list("Select a wordlist to use:", wordlists)
    return wordlists[choice - 1]

def main():
    print("=== Bcrypt Password Cracker ===")
    db_path = input("Enter path to your SQLite database file: ").strip()
    if not os.path.isfile(db_path):
        print("Database file not found.")
        return

    users = load_users(db_path)
    if not users:
        print("No users found in database.")
        return

    max_workers = 16  # adjust as needed

    # User selection
    user_options = [u for u, _ in users]
    user_options.append("Crack ALL users")
    user_choice = select_from_list("\nSelect user to crack:", user_options)

    # Crack method selection
    method_options = [
        "Wordlist cracking",
        "4-digit numeric brute force",
        "Charset brute force",
        "Combined (wordlist -> numeric -> charset)"
    ]
    method_choice = select_from_list("\nSelect cracking method:", method_options)

    wordlist = None
    if method_choice in [1,4]:  # wordlist needed or optional
        wordlist = select_wordlist()

    if user_choice == len(user_options):  # Crack ALL users
        print("Grouping users by identical password hashes...")
        groups = group_users_by_hash(users)
        cracked_passwords = {}
        for hash_str, usernames in groups.items():
            print(f"\nCracking password hash for users: {', '.join(usernames)}")
            hash_bytes = hash_str.encode('utf-8')
            password = crack_password(hash_bytes, method_choice, wordlist, max_workers)
            if password:
                print(f"Found password for users {', '.join(usernames)}: {password}")
                for u in usernames:
                    cracked_passwords[u] = password
            else:
                print(f"Could not crack password for users {', '.join(usernames)}")
        print("\n=== Summary of cracked passwords ===")
        for u, p in cracked_passwords.items():
            print(f"{u}: {p}")
    else:
        username = user_options[user_choice - 1]
        found = False
        for u, h in users:
            if u == username:
                hash_bytes = h.encode('utf-8')
                print(f"Cracking password for user {username}...")
                password = crack_password(hash_bytes, method_choice, wordlist, max_workers)
                if password:
                    print(f"Password found for {username}: {password}")
                else:
                    print(f"Password not found for {username}")
                found = True
                break
        if not found:
            print(f"User {username} not found in database.")

if __name__ == '__main__':
    main()
