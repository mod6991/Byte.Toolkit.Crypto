from Crypto.Random import get_random_bytes
from struct import pack, unpack
from typing import BinaryIO
from Crypto.Hash import SHA3_512


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
    with open(r'sha3.dat', 'wb') as sha3_dat,\
         open(r'sha3.txt', 'w') as sha3_good:
        
        write_l(sha3_dat, 100)
        
        for i in range(100):
            data = get_random_bytes(i)
            write_lv(sha3_dat, data)

            sha3 = SHA3_512.new(data)
            hash= sha3.digest().hex()
            sha3_good.write(f"{hash}\n")

    with open('sha3.dat', 'rb') as sha3_dat:
        data = sha3_dat.read()
        sha3 = SHA3_512.new(data)
    
    with open('sha3.dat.txt', 'w') as sha3_dat_txt:
        sha3_dat_txt.write(sha3.hexdigest())
    

if __name__ == '__main__':
    main()
