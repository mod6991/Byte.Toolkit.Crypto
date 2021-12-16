from Crypto.Random import get_random_bytes
from base64 import b64encode
from Crypto.Hash import MD5

def main():
    with open(r'data\md5.csv', 'w') as file:
        file.write('Base64,MD5 hash\n')
        for i in range(1, 500 + 1):
            data = get_random_bytes(i)
            md5 = MD5.new(data)
            file.write(f"{b64encode(data).decode()},{md5.digest().hex()}\n")

if __name__ == '__main__':
    main()
