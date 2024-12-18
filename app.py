import os
import base64
import re
from passlib.context import CryptContext
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import subprocess

# Set up Passlib context for hashing passwords using bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# AES Encryption and Decryption functions
def encrypt_password(password, key):
    """
    Encrypts the password using AES (CBC mode) with the given key.
    """
    iv = os.urandom(16)  # Generate a random IV (Initialization Vector)
    padding_length = 16 - (len(password) % 16)  # Pad the password to be a multiple of 16
    password_padded = password + chr(padding_length) * padding_length
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_password = encryptor.update(password_padded.encode()) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_password).decode()

def decrypt_password(encrypted_password, key):
    """
    Decrypts the password using AES with the given key.
    """
    encrypted_data = base64.b64decode(encrypted_password)
    iv = encrypted_data[:16]
    encrypted_password = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_password_padded = decryptor.update(encrypted_password) + decryptor.finalize()
    padding_length = decrypted_password_padded[-1]
    decrypted_password = decrypted_password_padded[:-padding_length].decode()
    return decrypted_password

# Strong password validation function
def validate_password(password):
    """
    Validates if the password meets the strong password policy.
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one digit."
    if not re.search(r'[^a-zA-Z0-9]', password):
        return False, "Password must contain at least one special character."
    if re.search(r'(password|12345|qwerty|abc123)', password, re.I):
        return False, "Password is too common and easily guessable."
    return True, "Password is strong."

# Hashing function using Passlib's bcrypt
def hash_password(password):
    """
    Hashes the password using bcrypt.
    """
    return pwd_context.hash(password)

# Function to verify the password against a hash using Passlib
def verify_password(plain_password, hashed_password):
    """
    Verifies if the plain password matches the hashed password.
    """
    return pwd_context.verify(plain_password, hashed_password)

# Function for brute force with John the Ripper
def brute_force_john_the_ripper(hashed_password_file):
    """
    Performs brute force using John the Ripper on a password hash file.
    Assumes John the Ripper is installed and accessible via command line.
    """
    try:
        # Run John the Ripper from the command line on the hashed password file
        subprocess.run(['john', hashed_password_file], check=True)
        subprocess.run(['john', '--show', hashed_password_file], check=True)
        print("Brute-force attack completed.")
    except subprocess.CalledProcessError as e:
        print(f"Error running John the Ripper: {e}")

# Function to store encrypted password to a file
def store_encrypted_password(encrypted_password, filename):
    """
    Stores the encrypted password in a text file.
    """
    with open(filename, 'w') as file:
        file.write(encrypted_password)
    print(f"Encrypted password saved to {filename}")

# Main menu and logic for interaction
def main():
    while True:
        print("\nChoose an option:")
        print("1. Perform Brute Force with John the Ripper")
        print("2. Password Hashing, AES Encryption, and Decryption")
        print("3. Exit")

        choice = input("Enter your choice (1/2/3): ")

        if choice == '1':
            # Step 1: Enter password to hash and save for cracking
            password = input("Enter a password to hash: ")
            hashed_password = hash_password(password)

            # Step 2: Save hashed password to a file (simulating a hash file for cracking)
            hashed_password_file = "hashed_password.txt"
            with open(hashed_password_file, "w") as f:
                f.write(f"{hashed_password}\n")

            print(f"Hashed Password saved to {hashed_password_file}")

            # Step 3: Use John the Ripper to crack the password
            brute_force_john_the_ripper(hashed_password_file)

        elif choice == '2':
            # AES encryption key (must be 16, 24, or 32 bytes long)
            aes_key = os.urandom(32)  # Random 256-bit key

            password = input("Enter a password: ")

            # Validate the password against the strong password policy
            is_valid, message = validate_password(password)
            if is_valid:
                print("Password is strong.")

                # Hash the password using bcrypt (for storage and verification)
                hashed_password = hash_password(password)
                print(f"Hashed Password (bcrypt): {hashed_password}")

                # Encrypt the password using AES (for secure storage)
                encrypted_password = encrypt_password(password, aes_key)
                print(f"Encrypted Password (AES): {encrypted_password}")

                # Store the encrypted password in a text file
                store_encrypted_password(encrypted_password, "encrypted_password.txt")

                # Decrypt the password to verify
                verify = input("Do you want to decrypt and verify the password? (yes/no): ").lower()
                if verify == 'yes':
                    decrypted_password = decrypt_password(encrypted_password, aes_key)
                    print(f"Decrypted Password: {decrypted_password}")

                    # Verify against the hashed password
                    if verify_password(decrypted_password, hashed_password):
                        print("Password verified successfully!")
                    else:
                        print("Password verification failed.")
            else:
                print(f"Password is weak: {message}")

        elif choice == '3':
            print("Exiting the program. Goodbye!")
            break
        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    main()
