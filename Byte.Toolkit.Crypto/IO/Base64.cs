﻿using System;

namespace Byte.Toolkit.Crypto.IO
{
    public sealed class Base64DecodeException : Exception
    {
        public Base64DecodeException(string message) : base(message) { }
    }

    public static class Base64
    {
        private const string CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        private const char PADDING = '=';

        /// <summary>
        /// Encode bytes to Base64 string
        /// </summary>
        /// <param name="data">Byte array</param>
        /// <returns>Base64 string</returns>
        public static string Encode(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            int stringSize = data.Length % 3 == 0 ? (data.Length / 3) * 4 : (data.Length / 3 + 1) * 4;
            char[] ca = new char[stringSize];
            int loops = data.Length / 3;
            int mod = data.Length % 3;
            int i;
            byte b1, b2, b3;

            for (i = 0; i < loops; i++)
            {
                b1 = data[i * 3];
                b2 = data[i * 3 + 1];
                b3 = data[i * 3 + 2];
                ca[i * 4] = CHARS[b1 >> 2];
                ca[i * 4 + 1] = CHARS[(b1 & 0x03) << 4 | b2 >> 4];
                ca[i * 4 + 2] = CHARS[(b2 & 0x0f) << 2 | b3 >> 6];
                ca[i * 4 + 3] = CHARS[b3 & 0x3f];
            }

            if (mod == 2)
            {
                b1 = data[i * 3];
                b2 = data[i * 3 + 1];
                ca[i * 4] = CHARS[b1 >> 2];
                ca[i * 4 + 1] = CHARS[(b1 & 0x03) << 4 | b2 >> 4];
                ca[i * 4 + 2] = CHARS[(b2 & 0x0f) << 2];
                ca[i * 4 + 3] = PADDING;
            }
            else if (mod == 1)
            {
                b1 = data[i * 3];
                ca[i * 4] = CHARS[b1 >> 2];
                ca[i * 4 + 1] = CHARS[(b1 & 0x03) << 4];
                ca[i * 4 + 2] = PADDING;
                ca[i * 4 + 3] = PADDING;
            }

            return new string(ca);
        }

        /// <summary>
        /// Decode Base64 string to bytes
        /// </summary>
        /// <param name="str">Base64 string</param>
        /// <returns>Byte array</returns>
        public static byte[] Decode(string str)
        {
            if (str == null)
                throw new ArgumentNullException("str");

            if (str.Length % 4 != 0)
                throw new Base64DecodeException("Invalid input string length (not a multiple of 4)");

            byte[] data = new byte[(str.Length / 4) * 3];
            int loops = str.Length / 4;
            int i;
            int b1, b2, b3, b4;
            int paddings = 0;

            for (i = 0; i < loops; i++)
            {
                b1 = CHARS.IndexOf(str[i * 4]);
                if (b1 == -1)
                    throw new Base64DecodeException($"Invalid base64 char1 '{str[i * 4]}'");

                b2 = CHARS.IndexOf(str[i * 4 + 1]);
                if (b2 == -1)
                    throw new Base64DecodeException($"Invalid base64 char2 '{str[i * 4 + 1]}'");

                b3 = CHARS.IndexOf(str[i * 4 + 2]);
                if (b3 == -1 && str[i * 4 + 2] != PADDING)
                    throw new Base64DecodeException($"Invalid base64 char3 '{str[i * 4 + 2]}'");
                if (str[i * 4 + 2] == PADDING)
                    paddings++;

                b4 = CHARS.IndexOf(str[i * 4 + 3]);
                if (b4 == -1 && str[i * 4 + 3] != PADDING)
                    throw new Base64DecodeException($"Invalid base64 char4 '{str[i * 4 + 3]}'");
                if (str[i * 4 + 3] == PADDING)
                    paddings++;


                data[i * 3] = (byte)(b1 << 2 | b2 >> 4);
                data[i * 3 + 1] = (byte)((b2 & 0x0f) << 4 | b3 >> 2);
                data[i * 3 + 2] = (byte)((b3 & 0x03) << 6 | b4 & 0x3f);
            }

            if (paddings > 0)
            {
                byte[] newData = new byte[data.Length - paddings];
                Array.Copy(data, 0, newData, 0, data.Length - paddings);
                return newData;
            }

            return data;
        }
    }
}
