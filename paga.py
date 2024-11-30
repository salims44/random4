import ecdsa
import hashlib
import base58
import time
import requests
import secrets
from flask import Flask
from keep_alive import keep_alive

keep_alive()

app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello, World!'

def send_to_discord(content):
    webhook_url = 'https://discord.com/api/webhooks/1312512541041233950/9rHp78jxiyK8_X1gtXyRJ4inb77N62J8Sby9XLJNzdmXKY7fprjjCnw0t2PBD8wMuDob'
    data = {
        "content": content
    }

    try:
        response = requests.post(webhook_url, json=data)
        response.raise_for_status()
        time.sleep(0.2)
    except requests.exceptions.RequestException as e:
        print(f"Error sending message to Discord: {e}")

def private_key_to_public_key(private_key):
    sk = ecdsa.SigningKey.from_string(private_key.to_bytes(32, 'big'), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return b'\x02' + vk.to_string()[:32] if vk.to_string()[32] % 2 == 0 else b'\x03' + vk.to_string()[:32]

def public_key_to_address(public_key):
    sha256_bpk = hashlib.sha256(public_key).digest()
    ripemd160_bpk = hashlib.new('ripemd160', sha256_bpk).digest()
    prepend_network_byte = b'\x00' + ripemd160_bpk
    checksum = hashlib.sha256(hashlib.sha256(prepend_network_byte).digest()).digest()[:4]
    address = base58.b58encode(prepend_network_byte + checksum)
    return address.decode()

def main():
    target_pubkey = "02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16"
    target_address = "16RGFo6hjq9ym6Pj7N5H7L1NR1rVPJyw2v"

    print(f"Starting random private key search within range")
    send_to_discord(f"Starting random private key search within range")

    start_time = time.time()

    start = int("4000000000000000000000000000000000", 16)
    end = int("7fffffffffffffffffffffffffffffffff", 16)

    last_check_time = time.time()

    while True:
        private_key = secrets.randbelow(end - start) + start  

        current_time = time.time()
        if current_time - last_check_time >= 10:
            send_to_discord(f"Still checking...")
            last_check_time = current_time

        public_key = private_key_to_public_key(private_key)
        public_key_hex = public_key.hex()

        if public_key_hex == target_pubkey:
            match_message = (
                f"@everyone Public Key Match Found!\n"
                f"Private Key: {hex(private_key)}\n"
                f"Public Key: {public_key_hex}"
            )
            send_to_discord(match_message)

            wallet_address = public_key_to_address(public_key)
            if wallet_address == target_address:
                found_message = (
                    f"@everyone Found matching private key for target address: {hex(private_key)}"
                )
                send_to_discord(found_message)
                break

        time.sleep(0.005)

if __name__ == "__main__":
    main()
