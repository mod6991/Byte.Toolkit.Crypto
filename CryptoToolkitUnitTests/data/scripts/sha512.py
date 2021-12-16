from Crypto.Random import get_random_bytes
from base64 import b64encode
from Crypto.Hash import SHA512

def main():
    with open(r'..\sha512.csv', 'w') as file:
        file.write('Base64,SHA512 hash\n')
        for i in range(1, 500 + 1):
            data = get_random_bytes(i)
            sha512 = SHA512.new(data)
            file.write(f"{b64encode(data).decode()},{sha512.digest().hex()}\n")
    
    sha512 = SHA512.new(b'')
    print(sha512.digest().hex())
    sha512 = SHA512.new(b'abc')
    print(sha512.digest().hex())

if __name__ == '__main__':
    main()
