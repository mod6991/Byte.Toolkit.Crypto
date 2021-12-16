from Crypto.Random import get_random_bytes
from base64 import b64encode

def main():
    with open(r'data\hex_base64.csv', 'w') as file:
        file.write('Hex,Base64\n')
        for i in range(1, 500 + 1):
            data = get_random_bytes(i)
            file.write(f"{data.hex()},{b64encode(data).decode()}\n")

if __name__ == '__main__':
    main()
