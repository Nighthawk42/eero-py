import requests
import os
import json
import csv
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
    salt = os.urandom(16)  # Generate a unique salt
    key = derive_key(passphrase, salt)
    iv = os.urandom(16)  # Generate a unique IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(salt + iv + ct).decode()

def decrypt_data(encrypted_data, passphrase):
    encrypted_data = base64.b64decode(encrypted_data.encode())
    salt = encrypted_data[:16]  # Extract the salt
    iv = encrypted_data[16:32]  # Extract the IV
    ct = encrypted_data[32:]  # Extract the ciphertext
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

    def get_account(self):
        url = f"{BASE_URL}account"
        response = requests.get(url, headers=self.headers)
        if response.status_code == 200:
            return response.json()["data"]
        else:
            raise Exception(f"Account retrieval failed: {response.text}")

    def get_networks(self):
        account_data = self.get_account()
        return account_data["networks"]["data"]

    def get_devices(self):
        networks = self.get_networks()
        devices = []
        for network in networks:
            network_id = network["url"].split("/")[-1]
            url = f"{BASE_URL}networks/{network_id}/devices"
            response = requests.get(url, headers=self.headers)
            if response.status_code == 200:
                devices.extend(response.json()["data"])
            else:
                raise Exception(f"Device retrieval failed: {response.text}")
        return devices

@click.group()
@click.option('--session-file', default=SESSION_FILE, help='Session file to load/save session token')
@click.pass_context
def cli(ctx, session_file):
    ctx.ensure_object(dict)
    ctx.obj['SESSION_FILE'] = session_file
    passphrase = getpass("Enter passphrase for decrypting session token: ")
    if os.path.exists(session_file):
        with open(session_file, 'r') as file:
            encrypted_token = file.read().strip()
        session_token = decrypt_data(encrypted_token, passphrase)
        ctx.obj['CLIENT'] = EeroClient(session_token)
    else:
        ctx.obj['CLIENT'] = EeroClient()

def save_to_file(data, output_file):
    if output_file.endswith('.json'):
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"Data saved to {output_file}")
    elif output_file.endswith('.csv'):
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            if isinstance(data, list):
                headers = data[0].keys()
                writer.writerow(headers)
                for row in data:
                    writer.writerow(row.values())
            else:
                writer.writerow(data.keys())
                writer.writerow(data.values())
        print(f"Data saved to {output_file}")
    else:
        print(f"Unsupported file format: {output_file}")

@cli.command()
@click.option('--output', default=None, help='Output file to save the data in JSON or CSV format')
@click.pass_context
def account(ctx, output):
    client = ctx.obj['CLIENT']
    account_data = client.get_account()
    if output:
        save_to_file(account_data, output)
    else:
        print(json.dumps(account_data, indent=2))

@cli.command()
@click.option('--output', default=None, help='Output file to save the data in JSON or CSV format')
@click.pass_context
def devices(ctx, output):
    client = ctx.obj['CLIENT']
    devices_data = client.get_devices()
    if output:
        save_to_file(devices_data, output)
    else:
        print(json.dumps(devices_data, indent=2))

@cli.command()
@click.option('--output', default=None, help='Output file to save the data in JSON or CSV format')
@click.pass_context
def networks(ctx, output):
    client = ctx.obj['CLIENT']
    networks_data = client.get_networks()
    if output:
        save_to_file(networks_data, output)
    else:
        print(json.dumps(networks_data, indent=2))

@cli.command()
@click.pass_context
def session(ctx):
    session_file = ctx.obj['SESSION_FILE']
    if os.path.exists(session_file):
        with open(session_file, 'r') as file:
            encrypted_token = file.read().strip()
        print(f"Encrypted token: {encrypted_token}")
    else:
        print("No session file found.")

if __name__ == "__main__":
    cli()
