from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from struct import pack, unpack
from typing import BinaryIO
from Crypto.PublicKey import RSA


def encrypt_key_stream(input_stream: BinaryIO,
                       output_stream: BinaryIO,
                       )


def read_lv(stream: BinaryIO):
    data_len = stream.read(4)
    value_len = unpack('i', data_len)[0]
    return stream.read(value_len)


def write_lv(stream: BinaryIO, value: bytes):
    data_len = pack('i', len(value))
    stream.write(data_len)
    stream.write(value)


def write_l(stream: BinaryIO, value: int):
    data_len = pack('i', value)
    stream.write(data_len)


def main():
    with open('aes.dat', 'wb') as aes_data_dat:
        write_l(aes_data_dat, 50)

        for i in range(1, 101):
            key = get_random_bytes(32)
            write_lv(aes_data_dat, key)
            iv = get_random_bytes(16)
            write_lv(aes_data_dat, iv)
            data = get_random_bytes(i * 16)
            write_lv(aes_data_dat, data)

            cipher = AES.new(key, AES.MODE_CBC, iv)
            enc = cipher.encrypt(data)
            write_lv(aes_data_dat, enc)


if __name__ == '__main__':
    main()
