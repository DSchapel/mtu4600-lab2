#!/usr/bin/env python3
"""
Instructor script to create encrypted challenge files
"""

import json
import os
from datetime import datetime
from pgp_crypto_lab import PGPCrypto
# import smtplib
# from email.message import EmailMessage

def create_instructor_keys():
    """Generate instructor key pair"""
    instructor = PGPCrypto("Lab Instructor", "jnorthey@mtu.edu")
    instructor.generate_keypair(4096)  # Larger key for instructor
    
    # Export keys
    instructor.export_public_key("instructor_public_key.pem")
    instructor.export_private_key("instructor_private_key.pem", "instructor_passphrase_2024")
    print("Instructor keys created!")
    return instructor

def create_student_challenges(instructor, student_list):
    """Create individual encrypted challenges for each student"""
    
    import csv
    challenges = []
    # Read from CSV file named 'students.csv' with columns: name,email,question
    with open("students.csv", newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if len(row) >= 3:
                name, email, question = row[0].strip(), row[1].strip(), row[2].strip()
                challenges.append((name, email, question))

    for student_name, student_email, question in challenges:
        challenge_content = {
            "studentname": student_name,
            "studentemail": student_email,
            "challenge": question,
            "timestamp": datetime.now().isoformat(),
            "instructions": "Answer this question and sign your response with your private key"
        }
        challenge_text = json.dumps(challenge_content, indent=2)

        # Sign the challenge
        signature = instructor.sign_message(challenge_text)

        signed_challenge = {
            "content": challenge_content,
            "signature": signature,
            "instructor_key_id": instructor.key_id
        }

        # Use hybrid encryption for the challenge file
        challenge_json = json.dumps(signed_challenge, indent=2)
        temp_plain_path = f"messages/challenge_{student_email.split('@')[0]}.json"
        with open(temp_plain_path, "w", encoding="utf-8") as f:
            f.write(challenge_json)

        output_path = f"messages/challenge_{student_email.split('@')[0]}.bin"
        instructor.hybrid_encrypt_file(temp_plain_path, instructor.public_key, output_path)

        os.remove(temp_plain_path)
        print(f"Hybrid encrypted challenge created for {student_name} <{student_email}>")

# def email_challenge_files(sender_email, sender_password, smtp_server, smtp_port):
#     """
#     Email each challenge file to the corresponding student using SMTP.
#     Assumes challenge files are named challenge_<username>.json and CSV contains email addresses.
#     """
#     import glob
#     files = glob.glob("challenge_*.json")
#     for file in files:
#         username = file.split('_')[1].split('.')[0]
#         # Try to reconstruct email from username and CSV
#         # Or, parse the file for the email field
#         with open(file, 'r', encoding='utf-8') as f:
#             import json
#             data = json.load(f)
#             student_email = data['content']['student']
#         msg = EmailMessage()
#         msg['Subject'] = 'Your Cryptography Lab Challenge'
#         msg['From'] = sender_email
#         msg['To'] = student_email
#         msg.set_content('Attached is your personalized cryptography challenge for the lab.')
#         with open(file, 'rb') as f:
#             msg.add_attachment(f.read(), maintype='application', subtype='json', filename=file)
#         with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
#             server.login(sender_email, sender_password)
#             server.send_message(msg)
#         print(f"Emailed {file} to {student_email}")

if __name__ == "__main__":
    instructor = create_instructor_keys()
    # Student list is now read from CSV inside create_student_challenges
    create_student_challenges(instructor, None)
