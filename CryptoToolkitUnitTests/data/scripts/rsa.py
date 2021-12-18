from typing import BinaryIO
from Crypto.Random import get_random_bytes
from base64 import b64encode
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

def save_private_key_to_pem(key: RSA,
                            output_stream: BinaryIO,
                            password: str,
                            protection: str = 'PBKDF2WithHMAC-SHA1AndAES256-CBC') -> None:
    """Save private RSA key
    :param key: RSA key
    :param output_stream: Output stream
    :param password: Password
    :param protection: Protection algorithm
    """
    encrypted_key = key.export_key(passphrase=password, pkcs=8, protection=protection)
    output_stream.write(encrypted_key)


def save_public_key_to_pem(key: RSA,
                           output_stream: BinaryIO) -> None:
    """Save public RSA key
    :param key: RSA key
    :param output_stream: Output stream
    """
    key_content = key.publickey().export_key()
    output_stream.write(key_content)


def encrypt(key: RSA,
            data: bytes) -> bytes:
    """Encrypt data with RSA key
    :param key: RSA key
    :param data: Data to encrypt
    :return: Encrypted data
    """
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(data)


def decrypt(key: RSA,
            data: bytes) -> bytes:
    """Decrypt data with RSA key
    :param key: RSA key
    :param data: Data to decrypt
    :return: Decrypted data
    """
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(data)


def main():
    rsa_key1 = RSA.generate(2048)
    rsa_key2 = RSA.generate(2048)

    with open(r'..\pub_key1.pem', 'wb') as pub_pem1:
        save_public_key_to_pem(rsa_key1, pub_pem1)

    with open(r'..\pk_key1.pem', 'wb') as pk_pem1:
        save_private_key_to_pem(rsa_key1, pk_pem1, 'test1234')

    with open(r'..\pub_key2.pem', 'wb') as pub_pem2:
        save_public_key_to_pem(rsa_key2, pub_pem2)

    with open(r'..\pk_key2.pem', 'wb') as pk_pem2:
        save_private_key_to_pem(rsa_key2, pk_pem2, None, None)

    with open(r'..\rsa1.csv', 'w') as file:
        file.write('Data,Enc\n')
        for i in range(1, 10 + 1):
            data = get_random_bytes(i * 16)
            enc = encrypt(rsa_key1, data)
            file.write(f"{b64encode(data).decode()},{b64encode(enc).decode()}\n")

    with open(r'..\rsa2.csv', 'w') as file:
        file.write('Data,Enc\n')
        for i in range(1, 10 + 1):
            data = get_random_bytes(i * 16)
            enc = encrypt(rsa_key2, data)
            file.write(f"{b64encode(data).decode()},{b64encode(enc).decode()}\n")
    
if __name__ == '__main__':
    main()
