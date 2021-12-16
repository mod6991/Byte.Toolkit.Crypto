from Crypto.Random import get_random_bytes
from base64 import b64encode
from Crypto.Hash import SHA3_512

def main():
    with open(r'..\sha3_512.csv', 'w') as file:
        file.write('Base64,SHA3_512 hash\n')
        for i in range(1, 500 + 1):
            data = get_random_bytes(i)
            sha3_512 = SHA3_512.new(data)
            file.write(f"{b64encode(data).decode()},{sha3_512.digest().hex()}\n")
    
    sha3_512 = SHA3_512.new(b'')
    print(sha3_512.digest().hex())
    sha3_512 = SHA3_512.new(b'abc')
    print(sha3_512.digest().hex())

if __name__ == '__main__':
    main()
