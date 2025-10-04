import json
import csv
import base64
import os
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Util.Padding import unpad
from Crypto.PublicKey import RSA
from datetime import datetime, timedelta
import cemms_custom_report_bills_serial_numbers_generators
from utilities import Utilities

TOTAL_COLUMNS_COUNT = 1778
COLUMN_BPJ = 1777 - TOTAL_COLUMNS_COUNT
COLUMN_BPI = 1776 - TOTAL_COLUMNS_COUNT
COLUMN_I = 8
COLUMN_J = 9
COUNTRY_OF_DESTINATION = "Philippines"


def load_rsa_private_key(private_key_path: str) -> RSA.RsaKey:
    """Load RSA private key from a PEM file."""
    try:
        with open(private_key_path, "rb") as f:
            key = RSA.import_key(f.read())
        return key
    except FileNotFoundError:
        print(f"Error: Private key file not found at {private_key_path}")
        exit()


def rsa_decrypt_session_key(
    encrypted_key_bytes: bytes, private_key: RSA.RsaKey
) -> bytes:
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


def spread(rate_statement, currency_code):
    currency_spread_dict = [
        spread_obj[currency_code]["spread"]
        for spread_obj in rate_statement
        if currency_code in spread_obj
    ]
    if not currency_spread_dict:
        return None
    return currency_spread_dict[0]


def process_csv_no_header(
    csv_path: str, al_file: str, rs_csv_path: str, private_key_path: str
):
    """Process CSV without headers using column indices."""
    private_key = load_rsa_private_key(private_key_path)

    with open(csv_path, newline="", encoding="utf-8") as csvfile:
        reader = csv.reader(csvfile)
        rate_statement_list = Utilities.rate_statement(rs_csv_path)
        serial_numbers = (
            cemms_custom_report_bills_serial_numbers_generators.get_serial_numbers(
                al_file
            )
        )
        # print(type(serial_numbers))

        trx_json = []

        for i, row in enumerate(reader, 1):
            # print(f"Row {i}: total columns = {len(row)}")
            # print(f"Row {i}: last 5 columns = {row[-5:]}")
            try:
                ciphertext_b64 = row[COLUMN_BPJ]
                encrypted_text_b64 = row[COLUMN_BPI]
                iv_str = f"{row[COLUMN_I]}{row[COLUMN_J]}"

                # RSA unwrap session key
                encrypted_key_bytes = base64.b64decode(ciphertext_b64)
                # print(f"\n\nRow {i}: Encrypted key length (bytes) = {len(encrypted_key_bytes)}")

                session_key = rsa_decrypt_session_key(encrypted_key_bytes, private_key)

                # AES ciphertext
                ciphertext_bytes = base64.b64decode(encrypted_text_b64)

                # IV (padded to 16 bytes)
                iv = iv_str.encode("utf-8").ljust(16, b"\0")

                # Decrypt AES
                plaintext_bytes = decrypt_aes256_cbc(ciphertext_bytes, session_key, iv)
                plaintext = plaintext_bytes.decode("utf-8")

                filter_bill_sn = [
                    f"{j['bill_currency']}_{j['bill_denomination']}_{j['bill_serial_number']}"
                    for j in serial_numbers
                    if Utilities.is_same_minute(
                        f"{Utilities.get_iso_date(row[8])} {Utilities.get_iso_time(row[9])}",
                        row[1564],
                        f"{j['bill_insertion_date']} {j['bill_insertion_time']}",
                        j["bill_currency"],
                    )
                ]
                data_str = plaintext
                entries = data_str.split("|")
                full_name = entries[5].split(":")[1]
                trx_obj = {}
                trx_obj["TRANSACTION_DATE"] = Utilities.get_iso_date(row[8])
                trx_obj["TIME"] = Utilities.get_iso_time(row[9])
                trx_obj["TERMINAL"] = row[5]
                trx_obj["CLIENT_FULL_NAME"] = full_name
                trx_obj["CLIENT_SURNAME"] = (full_name.split("  ")[0]).strip()
                trx_obj["CLIENT_GIVEN_NAMES"] = full_name.split("  ")[1].strip()
                trx_obj["SEX"] = entries[8].split(":")[1]
                trx_obj["ORIGIN_OF_FOREIGN_NOTES"] = Utilities.get_country_name(
                    entries[6].split(":")[1]
                )
                trx_obj["COUNTRY_OF_DESTINATION"] = COUNTRY_OF_DESTINATION
                trx_obj["ID_NUMBER"] = entries[7].split(":")[1]
                trx_obj["ID_TYPE"] = entries[4].split(":")[1][0]
                trx_obj["CUSTOMER_ADDRESS"] = Utilities.get_country_name(
                    entries[6].split(":")[1]
                )
                trx_obj["DOB"] = Utilities.get_dob(entries[4], entries[7])
                trx_obj["EXPIRE_DATE"] = entries[1].split(":")[1]
                trx_obj["CURRENCY"] = row[1564]
                trx_obj["FX_AMOUNT"] = row[1668]
                trx_obj["MID_RATE_(BCX)"] = f"=R{i + 1}+S{i + 1}"
                trx_obj["PHP_EQUIVALENT_(BCX)"] = f"=O{i + 1}*P{i + 1}"
                trx_obj["SPREAD"] = spread(rate_statement_list, row[1564])
                trx_obj["RATE_(FXM)"] = Utilities.get_rate_float_value(row[1565])
                trx_obj["PHP_EQUIVALENT_(FXM)"] = format(float(row[1759]), ".2f")
                trx_obj["SCHEDULED_AMOUNT"] = f"=O{i + 1}*S{i + 1}"
                trx_obj["RESULT"] = "Abnormal" if int(row[1762]) > 0 else "Normal"
                trx_obj["PROFIT_MARGIN"] = f"=Q{i + 1}-U{i + 1}"
                trx_obj["BILLS_SERIAL_NUMBERS"] = (
                    filter_bill_sn if len(filter_bill_sn) > 0 else ""
                )

                trx_json.append(trx_obj)

                # print(json_trx_obj)
            except Exception as e:
                print(f"Row {i}: Decryption failed: {e}")

        # JSON output
        trx_json_output = json.dumps(trx_json, ensure_ascii=False, indent=2)
        print(trx_json_output)

        # generating csv file
        now = datetime.now()
        rep_csv_file_name = (
            f"CUSTOM-REPORT_{csv_path}-{now.day}-{now.minute}-{now.second}.csv"
        )
        rep_folder_path = Utilities.report_folder_name()
        rep_file_path = os.path.join(rep_folder_path, rep_csv_file_name)
        if not os.path.exists(rep_folder_path):
            os.makedirs(rep_folder_path)

        with open(rep_file_path, mode="w", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=trx_json[0].keys())
            writer.writeheader()
            for entry in trx_json:
                writer.writerow(entry)


if __name__ == "__main__":
    PRIVATE_KEY_FILE = "private_key.pem"
    RS_CSV_FILE = "RS_CSV_20251003011200.csv"
    CL_CSV_FILE = "CL_CSV_20250930015834_SOL_PH_PII.csv"
    AL_FILE = "AL_20250911.txt"

    process_csv_no_header(CL_CSV_FILE, AL_FILE, RS_CSV_FILE, PRIVATE_KEY_FILE)
