#!/usr/bin/env python3
"""
PGP Cryptography Lab - Python Implementation
This module provides a simplified PGP implementation for educational purposes.
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os
import json
import hashlib
from datetime import datetime
import gnupg

class PGPCrypto:
    """
    A simplified PGP implementation for educational purposes
    """
    
    def __init__(self, name="", email=""):
        self.name = name
        self.email = email
        self.private_key = None
        self.public_key = None
        self.key_id = None
        
    def generate_keypair(self, key_size=2048):
        """
        Generate RSA key pair for PGP operations
        
        Args:
            key_size (int): Size of RSA key in bits (minimum 2048)
        
        Returns:
            dict: Key information including fingerprint
        """
        print(f"Generating {key_size}-bit RSA key pair for {self.name} <{self.email}>...")
        
        # TODO: Student Implementation Required
        # Generate RSA private key using cryptography library
        # Hint: Use rsa.generate_private_key()
        # In generate_keypair method, replace the TODO sections:
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        # TODO: Student Implementation Required  
        # Extract public key from private key
        self.public_key = self.private_key.public_key()
        
        # Generate key ID (first 8 bytes of SHA-1 hash of public key)
        public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        key_hash = hashlib.sha1(public_key_bytes).hexdigest()
        self.key_id = key_hash[-16:].upper()
        
        key_info = {
            'key_id': self.key_id,
            'key_size': key_size,
            'created': datetime.now().isoformat(),
            'owner': f"{self.name} <{self.email}>"
        }
        
        print(f"Key pair generated successfully!")
        print(f"Key ID: {self.key_id}")
        return key_info
    
    def export_public_key(self, filename=None):
        """
        Export public key in PEM format
        
        Args:
            filename (str): Optional filename, defaults to keyid_public.pem
            
        Returns:
            str: Public key in PEM format
        """
        if not self.public_key:
            raise ValueError("No public key available. Generate a key pair first.")
        
        # TODO: Student Implementation Required
        # Export public key in PEM format
        # Hint: Use public_key.public_bytes()
        # In export_public_key method:
        pem_data = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        if filename is None:
            filename = f"{self.key_id}_public.pem"
        
        with open(filename, 'wb') as f:
            f.write(pem_data)
        
        print(f"Public key exported to {filename}")
        return pem_data.decode('utf-8')
    
    def export_private_key(self, filename=None, passphrase=None):
        """
        Export private key in PEM format with optional passphrase protection
        
        Args:
            filename (str): Optional filename
            passphrase (str): Optional passphrase for key protection
        """
        if not self.private_key:
            raise ValueError("No private key available. Generate a key pair first.")
        
        if filename is None:
            filename = f"{self.key_id}_private.pem"
        
        # TODO: Student Implementation Required
        # Export private key with optional passphrase encryption
        # Hint: Use different encryption_algorithm based on passphrase
        
        encryption_algo = serialization.NoEncryption()
        if passphrase:
            encryption_algo = serialization.BestAvailableEncryption(passphrase.encode())
        
        # In export_private_key method:
        pem_data = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algo
    )
        
        with open(filename, 'wb') as f:
            f.write(pem_data)
        
        print(f"Private key exported to {filename}")
    
    def import_public_key(self, key_data):
        """
        Import a public key from PEM data
        
        Args:
            key_data (str or bytes): PEM formatted public key
            
        Returns:
            object: Loaded public key object
        """
        if isinstance(key_data, str):
            key_data = key_data.encode('utf-8')
        
        # Load public key from PEM data
        public_key = serialization.load_pem_public_key(
            key_data,
            backend=default_backend()
        )
        
        return public_key
    
    def import_private_key(self, key_data, passphrase=None):
        """
        Import a private key from PEM data
        
        Args:
            key_data (str or bytes): PEM formatted private key
            passphrase (str): Optional passphrase
            
        Returns:
            object: Loaded private key object
        """
        if isinstance(key_data, str):
            key_data = key_data.encode('utf-8')
        
        password = passphrase.encode() if passphrase else None
        
        # Load private key from PEM data
        private_key = serialization.load_pem_private_key(
                key_data,
                password=password,
                backend=default_backend()
            )
        
        return private_key
    
    def encrypt_message(self, message, recipient_public_key):
        """
        Encrypt a message using recipient's public key (RSA-OAEP)
        
        Args:
            message (str): Plain text message
            recipient_public_key: Public key object
            
        Returns:
            str: Base64 encoded encrypted message
        """
        # TODO: Student Implementation Required
        # 1. Convert message to bytes
        # 2. Encrypt using RSA-OAEP padding
        # 3. Return base64 encoded result
        
        message_bytes = message.encode('utf-8')
        
        # Implement RSA encryption here
        encrypted = recipient_public_key.encrypt(
            message_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return base64.b64encode(encrypted).decode('utf-8')
    
    def decrypt_message(self, encrypted_message_b64, private_key=None):
        """
        Decrypt a message using private key
        
        Args:
            encrypted_message_b64 (str): Base64 encoded encrypted message
            private_key: Private key object (uses self.private_key if None)
            
        Returns:
            str: Decrypted plain text message
        """
        if private_key is None:
            private_key = self.private_key
            
        if not private_key:
            raise ValueError("No private key available for decryption")
        
        # TODO: Student Implementation Required
        # 1. Decode base64 message
        # 2. Decrypt using RSA-OAEP padding
        # 3. Return decoded string
        
        encrypted_bytes = base64.b64decode(encrypted_message_b64)
        
        # Implement RSA decryption here
        # In decrypt_message method:
        decrypted = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return decrypted.decode('utf-8')
    
    def sign_message(self, message, private_key=None):
        """
        Create a digital signature for a message
        
        Args:
            message (str): Message to sign
            private_key: Private key for signing (uses self.private_key if None)
            
        Returns:
            str: Base64 encoded signature
        """
        if private_key is None:
            private_key = self.private_key
            
        if not private_key:
            raise ValueError("No private key available for signing")
        
        message_bytes = message.encode('utf-8')
        
            # Create digital signature using PSS padding and SHA-256
        signature = private_key.sign(
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return base64.b64encode(signature).decode('utf-8')
    
    def verify_signature(self, message, signature_b64, public_key):
        """
        Verify a digital signature
        
        Args:
            message (str): Original message
            signature_b64 (str): Base64 encoded signature
            public_key: Public key for verification
            
        Returns:
            bool: True if signature is valid
        """
        try:
            message_bytes = message.encode('utf-8')
            signature_bytes = base64.b64decode(signature_b64)
            
                # Verify signature using PSS padding and SHA-256
            public_key.verify(
                signature_bytes,
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False
    
    def hybrid_encrypt_file(self, file_path, recipient_public_key, output_path):
        """
        Encrypt a file using hybrid encryption (AES + RSA)
        Large files use AES for speed, RSA encrypts the AES key
        
        Args:
            file_path (str): Path to file to encrypt
            recipient_public_key: Recipient's public key
            output_path (str): Path for encrypted output
        """
        # Generate random AES key
        aes_key = os.urandom(32)  # 256-bit key
        iv = os.urandom(16)       # 128-bit IV
        
        # 1. Encrypt the AES key with recipient's RSA public key
        encrypted_aes_key = recipient_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 2. Encrypt file content with AES-CBC
        with open(file_path, 'rb') as f:
            plaintext = f.read()

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        # Pad plaintext to block size (AES block size is 16 bytes)
        pad_len = 16 - (len(plaintext) % 16)
        padded_plaintext = plaintext + bytes([pad_len] * pad_len)
        encrypted_content = encryptor.update(padded_plaintext) + encryptor.finalize()

        # 3. Create output format: [encrypted_aes_key][iv][encrypted_content]
        with open(output_path, 'wb') as out:
            out.write(encrypted_aes_key)
            out.write(iv)
            out.write(encrypted_content)

        print(f"File {file_path} encrypted to {output_path}")
    
    def get_key_fingerprint(self, public_key=None):
        """
        Generate key fingerprint (SHA-1 hash of public key)
        
        Args:
            public_key: Public key object (uses self.public_key if None)
            
        Returns:
            str: Formatted fingerprint
        """
        if public_key is None:
            public_key = self.public_key
            
        if not public_key:
            raise ValueError("No public key available")
        
        # Get public key bytes
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Generate SHA-1 fingerprint
        fingerprint = hashlib.sha1(public_bytes).hexdigest().upper()
        
        # Format as standard PGP fingerprint (groups of 4)
        formatted = ' '.join([fingerprint[i:i+4] for i in range(0, len(fingerprint), 4)])
        return formatted

class GPGIntegration:
    """
    Integration with system GPG for validation and testing
    """
    
    def __init__(self):
        self.gpg = gnupg.GPG()
    
    def compare_with_gpg(self, python_public_key, gpg_key_id):
        """
        Compare Python-generated key with GPG key
        Used for validation of implementation
        """
        # Get GPG public key
        gpg_keys = self.gpg.list_keys()
        gpg_key = None
        
        for key in gpg_keys:
            if gpg_key_id in key['keyid']:
                gpg_key = key
                break
        
        if not gpg_key:
            print(f"GPG key {gpg_key_id} not found")
            return False
        
        print(f"GPG Key: {gpg_key['keyid']}")
        print(f"Python Key fingerprint: {python_public_key}")
        
        return True
    
    def test_interoperability(self, message, python_encrypted, gpg_private_key_id):
        """
        Test if GPG can decrypt Python-encrypted message
        """
        try:
            # This would require more complex integration
            # Left as advanced exercise
            print("Interoperability testing would require additional GPG integration")
            return True
        except Exception as e:
            print(f"Interoperability test failed: {e}")
            return False

# Lab Exercise Functions
def lab_exercise_1():
    """
    Exercise 1: Basic Key Generation and Management
    """
    print("\n" + "="*50)
    print("EXERCISE 1: Key Generation and Management")
    print("="*50)
    
    # 1. Create a PGPCrypto instance with your name and email
    student_name = input("Enter your name: ")
    student_email = input("Enter your email: ")
    pgp = PGPCrypto(student_name, student_email)

    # 2. Generate a key pair
    pgp.generate_keypair()

    # 3. Export both public and private keys
    pub_pem = pgp.export_public_key()
    pgp.export_private_key()

    # 4. Display the key fingerprint
    fingerprint = pgp.get_key_fingerprint()
    print(f"Key Fingerprint: {fingerprint}")

def lab_exercise_2():
    """
    Exercise 2: Message Encryption and Decryption
    """
    print("\n" + "="*50)
    print("EXERCISE 2: Message Encryption/Decryption")
    print("="*50)
    
    # 1. Generate two key pairs (Alice and Bob)
    alice = PGPCrypto("Alice", "alice@example.com")
    bob = PGPCrypto("Bob", "bob@example.com")
    alice.generate_keypair()
    bob.generate_keypair()

    # 2. Have Alice encrypt a message for Bob
    message = input("Enter a message for Alice to send to Bob: ")
    encrypted_message = alice.encrypt_message(message, bob.public_key)
    print(f"Encrypted message (base64): {encrypted_message}")

    # 3. Have Bob decrypt the message
    decrypted_message = bob.decrypt_message(encrypted_message)
    print(f"Decrypted message: {decrypted_message}")

    # 4. Verify the round-trip works correctly
    if message == decrypted_message:
        print("Round-trip successful: Message matches!")
    else:
        print("Round-trip failed: Message does not match.")

def lab_exercise_3():
    """
    Exercise 3: Digital Signatures
    """
    print("\n" + "="*50)
    print("EXERCISE 3: Digital Signatures")
    print("="*50)
    
    # 1. Create a message and sign it
    alice = PGPCrypto("Alice", "alice@example.com")
    bob = PGPCrypto("Bob", "bob@example.com")
    alice.generate_keypair()
    bob.generate_keypair()

    message = input("Enter a message to sign: ")
    signature = alice.sign_message(message)
    print(f"Signature (base64): {signature}")

    # 2. Verify the signature
    valid = alice.verify_signature(message, signature, alice.public_key)
    print(f"Signature valid (Alice's public key): {valid}")

    # 3. Test signature verification with a tampered message
    tampered_message = message + " (tampered)"
    valid_tampered = alice.verify_signature(tampered_message, signature, alice.public_key)
    print(f"Signature valid for tampered message: {valid_tampered}")

    # 4. Test with wrong public key (Bob's)
    valid_wrong_key = alice.verify_signature(message, signature, bob.public_key)
    print(f"Signature valid with Bob's public key: {valid_wrong_key}")

def lab_exercise_4():
    """
    Exercise 4: GPG Integration and Validation
    """
    print("\n" + "="*50)
    print("EXERCISE 4: GPG Integration")
    print("="*50)
    

    print("GPG Commands to run:")
    print("1. gpg --full-generate-key")
    print("2. gpg --export --armor your-email@example.com > gpg_public_key.asc")
    print("3. gpg --fingerprint your-email@example.com")
    
    gpg_fingerprint = input("Enter your GPG key fingerprint: ")
    
    # Compare with Python implementation
    pgp = PGPCrypto("Student", "student@example.com")
    pgp.generate_keypair()
    python_fingerprint = pgp.get_key_fingerprint()
    
    print(f"GPG Fingerprint:    {gpg_fingerprint}")
    print(f"Python Fingerprint: {python_fingerprint}")

def lab_exercise_5():
    """
    Exercise 5: Decrypt Instructor's Challenge File
    """
    print("\n" + "="*50)
    print("EXERCISE 5: Instructor Challenge")
    print("="*50)
    
    # TODO: Student Implementation
    # 1. Load instructor's public key
    # 2. Decrypt the challenge file
    # 3. Verify the signature
    # 4. Answer the challenge question
    
    instructor_public_key_file = "instructor_public_key.pem"
    challenge_file = input("Enter the challenge file name (e.g., challenge_encrypted.txt or challenge.bin): ")
    
    try:
        # Load instructor's private key
        instructor_private_key_file = input("Enter the instructor's private key file name (e.g., instructor_private.pem): ")
        passphrase = input("Enter the instructor's private key passphrase (leave blank if none): ")
        with open(instructor_private_key_file, 'rb') as f:
            instructor_key_data = f.read()
        pgp = PGPCrypto()
        instructor_private_key = pgp.import_private_key(instructor_key_data, passphrase if passphrase else None)

        # Load hybrid encrypted challenge file (binary)
        with open(challenge_file, 'rb') as f:
            encrypted_data = f.read()

        # Hybrid format: [encrypted_aes_key][iv][encrypted_content]
        # Use correct RSA key size (4096 bits = 512 bytes)
        rsa_key_size_bytes = 512
        iv_size_bytes = 16
        encrypted_aes_key = encrypted_data[:rsa_key_size_bytes]
        iv = encrypted_data[rsa_key_size_bytes:rsa_key_size_bytes+iv_size_bytes]
        encrypted_content = encrypted_data[rsa_key_size_bytes+iv_size_bytes:]

        # Decrypt AES key with instructor's private key
        aes_key = instructor_private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Decrypt file content with AES-CBC
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(encrypted_content) + decryptor.finalize()
        # Remove PKCS#7 padding
        pad_len = padded_plaintext[-1]
        plaintext = padded_plaintext[:-pad_len]

        # Assume the decrypted content is JSON
        try:
            challenge_json = json.loads(plaintext.decode('utf-8'))
            print("Decrypted challenge file:")
            print(json.dumps(challenge_json, indent=2))
        except Exception as e:
            print("Decryption succeeded, but failed to parse JSON:", e)
            print("Raw decrypted content:")
            print(plaintext.decode('utf-8', errors='replace'))
    except FileNotFoundError as e:
        print(f"Required file not found: {e}")
        print("Make sure you have your private key and the challenge file.")

def bonus_exercise():
    """
    Bonus: Advanced PGP Features
    """
    print("\n" + "="*50)
    print("BONUS EXERCISE: Advanced Features")
    print("="*50)
    
    # TODO: Student Implementation (Optional)
    # 1. Implement key revocation certificates
    # 2. Add key expiration dates
    # 3. Implement subkeys for different purposes
    # 4. Create a simple web of trust system
    
    pass

# Utility Functions
def test_implementation():
    """
    Test the PGP implementation with known test vectors
    """
    print("\n" + "="*50)
    print("TESTING YOUR IMPLEMENTATION")
    print("="*50)
    
    # Create test instance
    alice = PGPCrypto("Alice Test", "alice@test.com")
    alice.generate_keypair()
    
    bob = PGPCrypto("Bob Test", "bob@test.com")
    bob.generate_keypair()
    
    # Test message
    test_message = "This is a secret test message for the PGP lab!"
    
    try:
        # Test encryption/decryption
        encrypted = alice.encrypt_message(test_message, bob.public_key)
        decrypted = bob.decrypt_message(encrypted)
        
        print(f"Original:  {test_message}")
        print(f"Encrypted: {encrypted[:50]}...")
        print(f"Decrypted: {decrypted}")
        print(f"Round-trip successful: {test_message == decrypted}")
        
        # Test signing/verification
        signature = alice.sign_message(test_message)
        is_valid = bob.verify_signature(test_message, signature, alice.public_key)
        
        print(f"Signature valid: {is_valid}")
        
    except NotImplementedError:
        print("Implementation not complete yet. Finish the TODO sections first.")
    except Exception as e:
        print(f"Test failed: {e}")

def generate_lab_report_template():
    """
    Generate a template for the lab report
    """
    report_template = """
# PGP Cryptography Lab Report

**Student Name**: ___________________
**Date**: ___________________
**Lab Partner** (if any): ___________________

## Part 1: Implementation Analysis

### Key Generation
- Key size chosen: _____ bits
- Reasoning for key size: 
- Time taken to generate: _____ seconds

### Encryption/Decryption Testing
- Test message used: 
- Encryption successful: Y/N
- Decryption successful: Y/N
- Any issues encountered:

### Digital Signatures
- Signature generation successful: Y/N
- Signature verification successful: Y/N
- Tampered message correctly rejected: Y/N

## Part 2: GPG Comparison

### Key Fingerprints
- Python implementation fingerprint: 
- GPG tool fingerprint: 
- Do they match? Y/N
- If not, explain why:

### Performance Comparison
- Python encryption time: _____ ms
- GPG encryption time: _____ ms
- Observations:

## Part 3: Instructor Challenge

### Challenge Question
- Question from decrypted file: 
- Your answer: 
- Signature verification result: 

### Security Analysis
- What would happen if you used the wrong public key?
- How can you be sure the instructor's public key is authentic?
- What are the weaknesses of this PGP implementation?

## Part 4: Real-World Applications

### Research Findings
Choose one topic and write 2-3 paragraphs:
- How does Signal use similar cryptographic principles?
- Why did PGP adoption remain limited for email?
- How do Certificate Authorities differ from PGP's web of trust?

## Part 5: Code Improvements

List three improvements you would make to this PGP implementation for production use:
1. 
2. 
3. 

## Conclusion

What was the most challenging part of this lab?
What did you learn about public-key cryptography?
"""
    
    with open("lab_report_template.md", "w") as f:
        f.write(report_template)
    
    print("Lab report template created: lab_report_template.md")

# Main Lab Execution
def main():
    """
    Main lab execution function
    """
    print("PGP Cryptography Lab - Python Implementation")
    print("=" * 60)
    
    while True:
        print("\nChoose an exercise:")
        print("1. Key Generation and Management")
        print("2. Message Encryption/Decryption") 
        print("3. Digital Signatures")
        print("4. GPG Integration")
        print("5. Instructor Challenge")
        print("6. Test Implementation")
        print("7. Generate Lab Report Template")
        print("8. Bonus Exercise")
        print("0. Exit")
        
        choice = input("\nEnter your choice (0-8): ")
        
        if choice == "1":
            lab_exercise_1()
        elif choice == "2":
            lab_exercise_2()
        elif choice == "3":
            lab_exercise_3()
        elif choice == "4":
            lab_exercise_4()
        elif choice == "5":
            lab_exercise_5()
        elif choice == "6":
            test_implementation()
        elif choice == "7":
            generate_lab_report_template()
        elif choice == "8":
            bonus_exercise()
        elif choice == "0":
            print("Lab session ended. Remember to complete your lab report!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()