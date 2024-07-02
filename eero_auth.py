import requests
import os
import click
import base64
from getpass import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

BASE_URL = "https://api-user.e2ro.com/2.2/"
SESSION_FILE = "eero_session"

def derive_key(passphrase, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

def encrypt_data(data, passphrase):
    salt = os.urandom(16)
    key = derive_key(passphrase, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(salt + iv + ct).decode()

def decrypt_data(encrypted_data, passphrase):
    encrypted_data = base64.b64decode(encrypted_data.encode())
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    ct = encrypted_data[32:]
    key = derive_key(passphrase, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data.decode()

class EeroClient:
    def __init__(self, session_token=""):
        self.session_token = session_token
        self.headers = {
            "Content-Type": "application/json",
        }
        if session_token:
            self.headers["Cookie"] = f"s={session_token}"

    def login(self, login):
        url = f"{BASE_URL}login"
        payload = {"login": login}
        response = requests.post(url, json=payload, headers=self.headers)
        if response.status_code == 200:
            return response.json()["data"]
        else:
            raise Exception(f"Login failed: {response.text}")

    def login_verify(self, session_token, verification_code):
        url = f"{BASE_URL}login/verify"
        payload = {"code": verification_code}
        headers = self.headers.copy()
        headers["Cookie"] = f"s={session_token}"
        response = requests.post(url, json=payload, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Verification failed: {response.text}")

@click.command()
@click.option('--session-file', default=SESSION_FILE, help='Session file to load/save session token')
def auth(session_file):
    while True:
        passphrase = getpass("Enter passphrase for encrypting session token: ")
        client = EeroClient()
        user_id = input("Enter Eero login ID (phone or email address): ").strip().lower()
        
        try:
            login_data = client.login(user_id)
            session_token = login_data["user_token"]
            verification_code = input("Enter OTP from Email or SMS: ").strip()
            client.login_verify(session_token, verification_code)
            encrypted_token = encrypt_data(session_token, passphrase)
            with open(session_file, 'w') as file:
                file.write(encrypted_token)
            print("Authentication successful.")
            break  # Exit the loop upon successful authentication
        except Exception as e:
            print(f"Error: {e}")
            retry = input("Login failed. Would you like to try again? (yes/no): ").strip().lower()
            if retry != 'yes':
                break  # Exit the loop if the user does not want to retry

if __name__ == "__main__":
    auth()
