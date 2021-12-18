from Crypto.Random import get_random_bytes
from base64 import b64encode
from Crypto.Hash import SHA1
from Crypto.Util.Padding import pad

def main():
    with open(r'..\iso7816.csv', 'w') as file:
        file.write('Base64,Iso7816 padding\n')
        for i in range(1, 500 + 1):
            data = get_random_bytes(i)
            padded = pad(data, 16, 'iso7816')
            file.write(f"{b64encode(data).decode()},{b64encode(padded).decode()}\n")
    
if __name__ == '__main__':
    main()