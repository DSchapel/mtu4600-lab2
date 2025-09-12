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
        self.private_key = None  # Replace with actual implementation
        
        # TODO: Student Implementation Required  
        # Extract public key from private key
        self.public_key = None  # Replace with actual implementation
        
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
        pem_data = None  # Replace with actual implementation
        
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
        
        pem_data = None  # Replace with actual implementation
        
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
        
        # TODO: Student Implementation Required
        # Load public key from PEM data
        # Hint: Use serialization.load_pem_public_key()
        public_key = None  # Replace with actual implementation
        
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
        
        # TODO: Student Implementation Required
        # Load private key from PEM data
        private_key = None  # Replace with actual implementation
        
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
        encrypted = None  # Replace with actual implementation
        
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
        decrypted = None  # Replace with actual implementation
        
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
        
        # TODO: Student Implementation Required
        # Create digital signature using PSS padding and SHA-256
        signature = None  # Replace with actual implementation
        
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
            
            # TODO: Student Implementation Required
            # Verify signature using PSS padding and SHA-256
            # Should not raise exception if valid
            
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
        
        # TODO: Student Implementation Required
        # 1. Encrypt the AES key with recipient's RSA public key
        # 2. Encrypt file content with AES-CBC
        # 3. Create output format: [encrypted_aes_key][iv][encrypted_content]
        
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
    
    # TODO: Student Implementation
    # 1. Create a PGPCrypto instance with your name and email
    # 2. Generate a key pair
    # 3. Export both public and private keys
    # 4. Display the key fingerprint
    
    student_name = input("Enter your name: ")
    student_email = input("Enter your email: ")
    
    pgp = PGPCrypto(student_name, student_email)
    
    # Student completes implementation here
    pass

def lab_exercise_2():
    """
    Exercise 2: Message Encryption and Decryption
    """
    print("\n" + "="*50)
    print("EXERCISE 2: Message Encryption/Decryption")
    print("="*50)
    
    # TODO: Student Implementation
    # 1. Generate two key pairs (Alice and Bob)
    # 2. Have Alice encrypt a message for Bob
    # 3. Have Bob decrypt the message
    # 4. Verify the round-trip works correctly
    
    pass

def lab_exercise_3():
    """
    Exercise 3: Digital Signatures
    """
    print("\n" + "="*50)
    print("EXERCISE 3: Digital Signatures")
    print("="*50)
    
    # TODO: Student Implementation
    # 1. Create a message and sign it
    # 2. Verify the signature
    # 3. Test signature verification with a tampered message
    # 4. Test with wrong public key
    
    pass

def lab_exercise_4():
    """
    Exercise 4: GPG Integration and Validation
    """
    print("\n" + "="*50)
    print("EXERCISE 4: GPG Integration")
    print("="*50)
    
    # TODO: Student Implementation
    # 1. Generate a key pair in GPG using command line
    # 2. Export the GPG public key
    # 3. Compare fingerprints between Python and GPG implementations
    # 4. Document any differences
    
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
    challenge_file = "challenge_encrypted.txt"
    
    try:
        # Load instructor's public key
        with open(instructor_public_key_file, 'r') as f:
            instructor_key_data = f.read()
        
        pgp = PGPCrypto()
        instructor_public_key = pgp.import_public_key(instructor_key_data)
        
        # Load and decrypt challenge file
        with open(challenge_file, 'r') as f:
            encrypted_challenge = f.read()
        
        # TODO: Implement decryption and signature verification
        print("Challenge file loaded. Implement decryption to continue.")
        
    except FileNotFoundError as e:
        print(f"Required file not found: {e}")
        print("Make sure you have the instructor's public key and challenge file.")

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