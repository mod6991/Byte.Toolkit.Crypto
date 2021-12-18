// HEXADECIMAL BYTES AND CHARS TABLE:
// ----------------------------------
// Byte            Char 
// 0  0000 0000 >> '0'  0011 0000
// 1  0000 0001 >> '1'  0011 0001
// 2  0000 0010 >> '2'  0011 0010
// 3  0000 0011 >> '3'  0011 0011
// 4  0000 0100 >> '4'  0011 0100
// 5  0000 0101 >> '5'  0011 0101
// 6  0000 0110 >> '6'  0011 0110
// 7  0000 0111 >> '7'  0011 0111
// 8  0000 1000 >> '8'  0011 1000
// 9  0000 1001 >> '9'  0011 1001
// 
// a  0000 1010 >> 'a'  0110 0001
// b  0000 1011 >> 'b'  0110 0010
// c  0000 1100 >> 'c'  0110 0011
// d  0000 1101 >> 'd'  0110 0100
// e  0000 1110 >> 'e'  0110 0101
// f  0000 1111 >> 'f'  0110 0110
// 
// a  0000 1010 >> 'A'  0100 0001
// b  0000 1011 >> 'B'  0100 0010
// c  0000 1100 >> 'C'  0100 0011
// d  0000 1101 >> 'D'  0100 0100
// e  0000 1110 >> 'E'  0100 0101
// f  0000 1111 >> 'F'  0100 0110

using System;

namespace Byte.Toolkit.Crypto.IO
{
    public sealed class HexDecodeException : Exception
    {
        public HexDecodeException(string message) : base(message) { }
    }

    public static class Hex
    {
        /// <summary>
        /// Encode bytes to hex string
        /// </summary>
        /// <param name="data">Byte array</param>
        /// <returns>Hex string</returns>
        public static string Encode(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            char[] ca = new char[data.Length * 2];
            byte b;

            for (int i = 0; i < data.Length; i++)
            {
                // ## Nibbles < 0x0a ##
                // --------------------
                // The right nibble of the bytes 0-9 (b < 0x0a) is the same as the right nibble of the chars '0'-'9'.
                // Example: byte 0x06 -> 0000 0110, char '6'  -> 0011 0110
                // So we just need to: b | 0x30
                // 
                // ## Nibbles >= 0x0a ##
                // ---------------------
                // The left nibble of the bytes a-f (b >= 0x0a) must to be set to 0110
                // -> b | 0x60
                // 
                // For the right nibble we must decrease the nibble value by 1 and set the left-most bit to 0.
                // -> ((b - 1) & 0x07)
                // 
                // final operation: ((b - 1) & 0x07) | 0x60

                // left nibble of the byte to encode
                b = (byte)(data[i] >> 4);
                ca[i * 2] = (char)(b < 0x0a ? b | 0x30 : ((b - 1) & 0x07) | 0x60);
                // right nibble of the byte to encode
                b = (byte)(data[i] & 0x0f);
                ca[i * 2 + 1] = (char)(b < 0x0a ? b | 0x30 : ((b - 1) & 0x07) | 0x60);
            }

            return new string(ca);
        }

        /// <summary>
        /// Decode hex string to bytes
        /// </summary>
        /// <param name="str">Hex string</param>
        /// <returns>Byte array</returns>
        public static byte[] Decode(string str)
        {
            if (str == null)
                throw new ArgumentNullException("str");

            if (str.Length % 2 != 0)
                throw new HexDecodeException("Invalid input string length (not a multiple of 2)");

            byte[] data = new byte[str.Length / 2];
            char c1, c2;
            int b1, b2;

            for (int i = 0; i < data.Length; i++)
            {
                c1 = str[i * 2];
                c2 = str[i * 2 + 1];

                if (!((c1 >= 0x30 && c1 <= 0x39) || (c1 >= 0x61 && c1 <= 0x66) || (c1 >= 0x41 && c1 <= 0x46)))
                    throw new HexDecodeException($"Invalid hex char '{c1}'");

                if (!((c2 >= 0x30 && c2 <= 0x39) || (c2 >= 0x61 && c2 <= 0x66) || (c2 >= 0x41 && c2 <= 0x46)))
                    throw new HexDecodeException($"Invalid hex char '{c2}'");

                // ## Chars '0'-'9' (c & 0xf0 == 0x30) ##
                // --------------------------------------
                // To get the corresponding byte of the chars '0'-'9', we need to set the left nibble to all-zeros
                // -> c & 0x0f
                // 
                // ## Chars 'a'-'f' (c & 0xf0 != 0x30) ##
                // --------------------------------------
                // To get the corresponding byte of the chars 'a'-'f', we first need to set the left nibble to all-zeros :
                // -> c & 0x0f
                // 
                // And for the right nibble, we need to set the left-most bit to 1 and add 1 to the value :
                // -> (c | 0x08) + 1
                // 
                // final operation: ((c & 0x0f) | 0x08) + 1

                b1 = (c1 & 0xf0) == 0x30 ? c1 & 0x0f : ((c1 & 0x0f) | 0x08) + 1;
                b2 = (c2 & 0xf0) == 0x30 ? c2 & 0x0f : ((c2 & 0x0f) | 0x08) + 1;
                data[i] = (byte)(b1 << 4 | b2);
            }

            return data;
        }
    }
}
