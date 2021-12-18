from Crypto.Random import get_random_bytes
from base64 import b64encode
from Crypto.Cipher import DES3

def main():
    with open(r'..\tripledes.csv', 'w') as file:
        file.write('Key,IV,Data,Encrypted\n')
        for i in range(1, 100 + 1):
            key = get_random_bytes(24)
            iv = get_random_bytes(8)
            data = get_random_bytes(i * 16)

            cipher = DES3.new(key, DES3.MODE_CBC, iv)
            enc = cipher.encrypt(data)
            file.write(f"{b64encode(key).decode()},{b64encode(iv).decode()},{b64encode(data).decode()},{b64encode(enc).decode()}\n")
    
if __name__ == '__main__':
    main()
