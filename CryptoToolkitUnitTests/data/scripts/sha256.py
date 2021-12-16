from Crypto.Random import get_random_bytes
from base64 import b64encode
from Crypto.Hash import SHA256

def main():
    with open(r'..\sha256.csv', 'w') as file:
        file.write('Base64,SHA256 hash\n')
        for i in range(1, 500 + 1):
            data = get_random_bytes(i)
            sha256 = SHA256.new(data)
            file.write(f"{b64encode(data).decode()},{sha256.digest().hex()}\n")
    
    sha256 = SHA256.new(b'')
    print(sha256.digest().hex())
    sha256 = SHA256.new(b'abc')
    print(sha256.digest().hex())

if __name__ == '__main__':
    main()
