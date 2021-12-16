from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA1

def main():
    with open(r'..\pbkdf2.csv', 'w') as file:
        file.write('Password,Salt,Key\n')
        for i in range(1, 100 + 1):
            password = get_random_bytes(8).hex()
            salt = get_random_bytes(16)
            key = PBKDF2(password, salt, 32, count=50000, hmac_hash_module=SHA1).hex()
            file.write(f"{password},{salt.hex()},{key}\n")
    
if __name__ == '__main__':
    main()
