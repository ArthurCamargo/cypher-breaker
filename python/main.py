from Crypto.Cipher import AES
import string
import itertools
import binascii

def decrypt_ecb(key, cipher_text):
    """
    Attempt to decrypt the cipher_text with the given key using AES-128-ECB.
    """
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = cipher.decrypt(cipher_text)
        return decrypted
    except ValueError:
        return None

def is_valid_plain_text(data):
    """
    Simple heuristic to determine if the decrypted text looks valid.
    Checks if all characters are printable ASCII or whitespace.
    """
    return all((32 <= b <= 126) or b == 10 or b == 13 for b in data)

def brute_force_aes_ecb(cipher_text_hex):
    """
    Brute force AES-128-ECB cipher with a 5-byte key consisting of [a-zA-Z0-9].
    """
    charset = string.ascii_letters + string.digits  # [a-zA-Z0-9]
    cipher_text = binascii.unhexlify(cipher_text_hex)

    # Generate all possible 5-character keys
    for key_tuple in itertools.product(charset, repeat=5):
        key = bytes("SecurityAES", 'utf-8')
        key += ''.join(key_tuple).encode('utf-8')
        decrypted = decrypt_ecb(key, cipher_text)
        if key == bytes("SecurityAESabcde", 'utf-8'):
            print(f"Testing : {key} - {decrypted}")
        if decrypted and is_valid_plain_text(decrypted):
            print(f"Key found: {key.decode('utf-8')}")
            print(f"Decrypted text: {decrypted.decode('utf-8', errors='ignore')}")
            return

    print("No valid key found!")

if __name__ == "__main__":
    # Example cipher text in hex (replace with your actual cipher text).
    cipher_text_hex = """0b31920620b869b19c631c3d4383a7c0d1d76aceaf9fcf1b70b6b5fbbbeba98ded52b0f3e3713c31421ef141ebadea621d5f58c65963a70b5def7f996a7c441baf93bdcd0f39160206a934060a786dd37c26669537d1457d2a584ef878c43bcdf5871d8c984c3f66ecec350a18ed3144f56d21dbd5f0ebdf0302414b1a4a1bbfaa81ce5f320cbe68247f380fa58727e755111141398d9ee126644b7962f58f02"""

    brute_force_aes_ecb(cipher_text_hex)
