from Crypto.Random import get_random_bytes
from base64 import b64encode
from Crypto.Cipher import AES

def main():
    with open(r'..\aes.csv', 'w') as file:
        file.write('Key,IV,Data,Encrypted\n')
        for i in range(1, 100 + 1):
            key = get_random_bytes(32)
            iv = get_random_bytes(16)
            data = get_random_bytes(i * 16)

            cipher = AES.new(key, AES.MODE_CBC, iv)
            enc = cipher.encrypt(data)
            file.write(f"{b64encode(key).decode()},{b64encode(iv).decode()},{b64encode(data).decode()},{b64encode(enc).decode()}\n")
    
if __name__ == '__main__':
    main()