﻿using System;

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
                throw new ArgumentNullException(nameof(data));

            char[] ca = new char[data.Length * 2];
            byte b;

            for (int i = 0; i < data.Length; i++)
            {
                b = (byte)(data[i] >> 4);
                ca[i * 2] = (char)(b < 0x0a ? b | 0x30 : ((b - 1) & 0x07) | 0x60);
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
                throw new ArgumentNullException(nameof(str));

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

                b1 = (c1 & 0xf0) == 0x30 ? c1 & 0x0f : ((c1 & 0x0f) | 0x08) + 1;
                b2 = (c2 & 0xf0) == 0x30 ? c2 & 0x0f : ((c2 & 0x0f) | 0x08) + 1;
                data[i] = (byte)(b1 << 4 | b2);
            }

            return data;
        }
    }
}
