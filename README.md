# password_toolkit
# Password Security Toolkit

## Overview
The Password Security Toolkit is a comprehensive project developed with **Cothon Solutions** to demonstrate the importance of password security and showcase various techniques for securing sensitive information. This project is designed to educate users on common vulnerabilities and best practices for password management, encryption, and security.

## Features
1. **Brute Force Attack Simulation**:
   - Demonstrates the process of cracking weak passwords using **John the Ripper**.
   - Highlights the risks of weak passwords and why strong passwords are essential.

2. **Password Hashing**:
   - Implements secure password hashing using **bcrypt** via the Passlib library.
   - Provides an example of how passwords should be stored securely in a hashed format to prevent unauthorized access.

3. **AES Encryption and Decryption**:
   - Encrypts passwords using the AES algorithm (CBC mode) to ensure data privacy.
   - Decrypts and verifies passwords securely when required.

4. **Strong Password Validation**:
   - Validates passwords against strict security policies (minimum length, special characters, no common patterns, etc.).
   - Ensures users create strong, unguessable passwords.

5. **Encrypted Password Storage**:
   - Stores encrypted passwords in a text file for secure record-keeping.

## How It Works
1. Users can choose from the following options via a user-friendly interface:
   - **Brute Force Simulation**: Enter a password to see how it can be cracked using John the Ripper.
   - **Password Security Features**: Hash, encrypt, and decrypt passwords, ensuring they meet strong security policies.
   - **Exit the Toolkit**: Safely terminate the program.

2. Passwords are securely hashed and encrypted, with the ability to decrypt them to demonstrate how secure storage and retrieval work.

3. Weak passwords can be cracked using brute force, showing the importance of adopting robust password practices.

## Technologies Used
- **Python**: Core programming language for implementation.
- **Passlib**: For password hashing with bcrypt.
- **Cryptography**: For AES encryption and decryption.
- **John the Ripper**: For brute force attack simulations.
- **Subprocess**: To run John the Ripper commands.

## Installation and Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/password-security-toolkit.git
   cd password-security-toolkit
   ```

2. Install dependencies:
   ```bash
   pip install passlib cryptography
   ```

3. Ensure **John the Ripper** is installed and accessible via your system's PATH. Installation instructions can be found [here](https://www.openwall.com/john/).

4. Run the program:
   ```bash
   python app.py
   ```

## Usage
- Select an option from the menu to:
  1. Perform brute force simulation.
  2. Hash, encrypt, or decrypt a password.
  3. Exit the program.
- Follow the on-screen prompts for each functionality.

## Benefits
- Educates users on password security.
- Demonstrates vulnerabilities of weak passwords.
- Provides a hands-on understanding of encryption, hashing, and secure storage.

## Contribution
Feel free to contribute by submitting pull requests or reporting issues. Let’s work together to improve password security awareness!

## Acknowledgments
This project was developed with **Cothon Solutions** to advance cybersecurity awareness and practices.

---

Thank you for checking out this project! If you found it interesting, feel free to connect with me on LinkedIn or visit our website to learn more about our work at **Cothon Solutions**.

#CyberSecurity #PasswordSecurity #JohnTheRipper #AES #Passlib #CothonSolutions

