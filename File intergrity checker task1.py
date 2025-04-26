import hashlib
import os
import json
import time

# Function to calculate the hash of a file
def calculate_file_hash(filepath, algorithm='sha256'):
    """
    Calculates the hash of a file using the specified algorithm.
    
    Args:
        filepath (str): Path to the file.
        algorithm (str): Hashing algorithm (default: sha256).

    Returns:
        str: Hexadecimal hash string.
    """
    hash_func = hashlib.new(algorithm)
    
    with open(filepath, 'rb') as f:
        while chunk := f.read(4096):
            hash_func.update(chunk)
    
    return hash_func.hexdigest()

# Function to scan all files in a directory and generate their hashes
def scan_directory(directory_path, algorithm='sha256'):
    """
    Scans a directory and calculates hashes for all files.
    
    Args:
        directory_path (str): Path to the directory.
        algorithm (str): Hashing algorithm.

    Returns:
        dict: Dictionary with file paths as keys and hashes as values.
    """
    file_hashes = {}
    for root, _, files in os.walk(directory_path):
        for file in files:
            full_path = os.path.join(root, file)
            try:
                file_hash = calculate_file_hash(full_path, algorithm)
                file_hashes[full_path] = file_hash
            except Exception as e:
                print(f"Failed to hash {full_path}: {e}")
    return file_hashes

# Function to save hashes to a JSON file
def save_hashes(hashes, output_file):
    """
    Saves file hashes into a JSON file.
    
    Args:
        hashes (dict): File hashes.
        output_file (str): Output JSON file path.
    """
    with open(output_file, 'w') as f:
        json.dump(hashes, f, indent=4)

# Function to load hashes from a JSON file
def load_hashes(hash_file):
    """
    Loads previously saved file hashes from a JSON file.
    
    Args:
        hash_file (str): Path to JSON file containing hashes.

    Returns:
        dict: File hashes.
    """
    if not os.path.exists(hash_file):
        print("Hash file not found.")
        return {}
    
    with open(hash_file, 'r') as f:
        return json.load(f)

# Function to compare current hashes with old hashes
def compare_hashes(old_hashes, new_hashes):
    """
    Compares old and new file hashes to detect changes.
    
    Args:
        old_hashes (dict): Previous file hashes.
        new_hashes (dict): Current file hashes.

    Returns:
        dict: Dictionary containing lists of added, removed, and modified files.
    """
    added = []
    removed = []
    modified = []

    old_files = set(old_hashes.keys())
    new_files = set(new_hashes.keys())

    added = list(new_files - old_files)
    removed = list(old_files - new_files)

    for file in old_files & new_files:
        if old_hashes[file] != new_hashes[file]:
            modified.append(file)

    return {
        "added": added,
        "removed": removed,
        "modified": modified
    }

# Main function to drive the tool
def main():
    print("="*50)
    print("Welcome to File Integrity Checker")
    print("="*50)

    directory_to_monitor = input("Enter the directory path to monitor: ").strip()
    hash_storage_file = input("Enter the path to save/load hash file (e.g., hashes.json): ").strip()
    algorithm = input("Enter hashing algorithm (default sha256): ").strip() or 'sha256'

    if not os.path.exists(directory_to_monitor):
        print(f"Directory '{directory_to_monitor}' does not exist.")
        return

    if os.path.exists(hash_storage_file):
        print("\n[*] Previous hash file found. Checking for changes...\n")
        old_hashes = load_hashes(hash_storage_file)
        new_hashes = scan_directory(directory_to_monitor, algorithm)
        changes = compare_hashes(old_hashes, new_hashes)

        if changes["added"]:
            print("[+] New files added:")
            for file in changes["added"]:
                print(f"    {file}")

        if changes["removed"]:
            print("[-] Files removed:")
            for file in changes["removed"]:
                print(f"    {file}")

        if changes["modified"]:
            print("[*] Files modified:")
            for file in changes["modified"]:
                print(f"    {file}")

        if not (changes["added"] or changes["removed"] or changes["modified"]):
            print("No changes detected. All files are intact.")

        # Update the hash file after checking
        save_hashes(new_hashes, hash_storage_file)

    else:
        print("\n[*] No previous hash file found. Creating new hash database...\n")
        hashes = scan_directory(directory_to_monitor, algorithm)
        save_hashes(hashes, hash_storage_file)
        print(f"Hash database created at '{hash_storage_file}'.")

    print("\nIntegrity check complete.")
    print("="*50)

if __name__ == "__main__":
    main()
