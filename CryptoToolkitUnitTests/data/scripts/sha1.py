from Crypto.Random import get_random_bytes
from base64 import b64encode
from Crypto.Hash import SHA1

def main():
    with open(r'..\sha1.csv', 'w') as file:
        file.write('Base64,SHA1 hash\n')
        for i in range(1, 500 + 1):
            data = get_random_bytes(i)
            sha1 = SHA1.new(data)
            file.write(f"{b64encode(data).decode()},{sha1.digest().hex()}\n")
    
    sha1 = SHA1.new(b'')
    print(sha1.digest().hex())
    sha1 = SHA1.new(b'abc')
    print(sha1.digest().hex())

if __name__ == '__main__':
    main()
