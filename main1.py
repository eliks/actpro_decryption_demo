import csv
import base64
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Util.Padding import unpad
from Crypto.PublicKey import RSA

TOTAL_COLUMNS_COUNT = 1778
COLUMN_BPJ = 1777 - TOTAL_COLUMNS_COUNT
COLUMN_BPI = 1776 - TOTAL_COLUMNS_COUNT
COLUMN_I   = 8
COLUMN_J   = 9

def load_rsa_private_key(private_key_path: str) -> RSA.RsaKey:
    """Load RSA private key from a PEM file."""
    try:
        with open(private_key_path, "rb") as f:
            key = RSA.import_key(f.read())
        return key
    except FileNotFoundError:
        print(f"Error: Private key file not found at {private_key_path}")
        exit()


def rsa_decrypt_session_key(encrypted_key_bytes: bytes, private_key: RSA.RsaKey) -> bytes:
    """Decrypt RSA-encrypted session key using PKCS1_v1_5."""
    cipher = PKCS1_v1_5.new(private_key)
    sentinel = None
    key = cipher.decrypt(encrypted_key_bytes, sentinel)
    if not key:
        raise ValueError("RSA decryption failed: invalid key or ciphertext")
    return key


def decrypt_aes256_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt AES-256-CBC ciphertext with PKCS#7 padding."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext


def process_csv_no_header(csv_path: str, private_key_path: str):
    """Process CSV without headers using column indices."""
    private_key = load_rsa_private_key(private_key_path)

    with open(csv_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)

        for i, row in enumerate(reader, 1):
            # print(f"Row {i}: total columns = {len(row)}")
            # print(f"Row {i}: last 5 columns = {row[-5:]}")
            try:
                
                ciphertext_b64 = row[COLUMN_BPJ]
                encrypted_text_b64 = row[COLUMN_BPI]
                iv_str = f"{row[COLUMN_I]}{row[COLUMN_J]}"

                # RSA unwrap session key
                encrypted_key_bytes = base64.b64decode(ciphertext_b64)
                print(f"\n\nRow {i}: Encrypted key length (bytes) = {len(encrypted_key_bytes)}")

                session_key = rsa_decrypt_session_key(encrypted_key_bytes, private_key)

                # AES ciphertext
                ciphertext_bytes = base64.b64decode(encrypted_text_b64)

                # IV (padded to 16 bytes)
                iv = iv_str.encode('utf-8').ljust(16, b'\0')

                # Decrypt AES
                plaintext_bytes = decrypt_aes256_cbc(ciphertext_bytes, session_key, iv)
                plaintext = plaintext_bytes.decode('utf-8')

                print(f"Row {i}: Decryption successful! Data: {plaintext}")

            except Exception as e:
                print(f"Row {i}: Decryption failed: {e}")


if __name__ == "__main__":
    PRIVATE_KEY_FILE = "private_key.pem"
    CSV_FILE = "CL_CSV_20250929074718.csv"

    process_csv_no_header(CSV_FILE, PRIVATE_KEY_FILE)
