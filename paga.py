import ecdsa
import hashlib
import base58
import time
import requests
import secrets
from flask import Flask
from keep_alive import keep_alive
import threading

# Keep the web server alive
keep_alive()

app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello, World!'

DISCORD_WEBHOOK_URL = 'https://discord.com/api/webhooks/1313675373875036302/mNeCS5D3HwygYRUuKDTHHAGJDRbez6GPm22c-6O_AmE0JmQC8qL2lZR6BD68_6Imh2li'

def send_to_discord(content):
    data = {"content": content}
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json=data)
        response.raise_for_status()
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

# Thread-safe counter for total keys checked
key_counter = 0
counter_lock = threading.Lock()

# Report keys checked per second periodically
def report_key_rate():
    global key_counter
    last_count = 0
    while True:
        time.sleep(1)
        with counter_lock:
            keys_checked = key_counter - last_count
            last_count = key_counter
        print(f"Keys checked per second: {keys_checked}")
        send_to_discord(f"Keys checked per second: {keys_checked}")

# Optimizing private key search and splitting it into threads
def search_for_private_key(start, end, target_pubkey, target_address):
    global key_counter
    print(f"Thread started searching from {start:x} to {end:x}")

    while True:
        private_key = secrets.randbelow(end - start) + start
        private_key_hex = f"{private_key:064x}"
        public_key = private_key_to_public_key(private_key)
        public_key_hex = public_key.hex()

        # Increment the global counter
        with counter_lock:
            key_counter += 1

        if public_key_hex == target_pubkey:
            match_message = (
                f"@everyone Public Key Match Found!\n"
                f"Private Key: {private_key_hex}\n"
                f"Public Key: {public_key_hex}"
            )
            send_to_discord(match_message)

            wallet_address = public_key_to_address(public_key)
            if wallet_address == target_address:
                found_message = (
                    f"@everyone Found matching private key for target address: {private_key_hex}"
                )
                send_to_discord(found_message)
                break

# Main function now handles parallel searches
def main():
    target_pubkey = "02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16"
    target_address = "16RGFo6hjq9ym6Pj7N5H7L1NR1rVPJyw2v"
    
    print(f"Starting random private key search within range")
    send_to_discord(f"Starting random private key search within range")

    start_time = time.time()

    start = int("4000000000000000000000000000000000", 16)
    end = int("7fffffffffffffffffffffffffffffffff", 16)

    # Split the range into multiple parts and run in parallel
    num_threads = 4
    thread_range = (end - start) // num_threads

    threads = []
    for i in range(num_threads):
        thread_start = start + i * thread_range
        thread_end = start + (i + 1) * thread_range if i < num_threads - 1 else end
        thread = threading.Thread(target=search_for_private_key, args=(thread_start, thread_end, target_pubkey, target_address))
        threads.append(thread)
        thread.start()

    # Start the key rate reporting thread
    rate_thread = threading.Thread(target=report_key_rate, daemon=True)
    rate_thread.start()

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

    print(f"Total search time: {time.time() - start_time} seconds")

if __name__ == "__main__":
    main()
