using Byte.Toolkit.Crypto.Random;
using System.Security.Cryptography;

namespace Byte.Toolkit.Crypto.Padding
{
    public class PaddingException : Exception
    {
        public PaddingException(string message) : base(message) { }
    }

    public enum PaddingStyle
    {
        None,
        Pkcs7,
        AnsiX923,
        Iso7816,
        Iso10126
    }

    public static class Padding
    {
        public static byte[] Pad(byte[] data, int blockSize, PaddingStyle paddingStyle)
        {
            switch (paddingStyle)
            {
                case PaddingStyle.None:
                    return data;
                case PaddingStyle.Pkcs7:
                    return PadPkcs7(data, blockSize);
                case PaddingStyle.AnsiX923:
                    return PadAnsiX923(data, blockSize);
                case PaddingStyle.Iso7816:
                    return PadIso7816(data, blockSize);
                case PaddingStyle.Iso10126:
                    return PadIso10126(data, blockSize);
                default:
                    throw new InvalidOperationException("Unknown padding style");
            }
        }

        public static byte[] Unpad(byte[] data, int blockSize, PaddingStyle paddingStyle)
        {
            switch (paddingStyle)
            {
                case PaddingStyle.None:
                    return data;
                case PaddingStyle.Pkcs7:
                    return UnpadPkcs7(data, blockSize);
                case PaddingStyle.AnsiX923:
                    return UnpadAnsiX923(data, blockSize);
                case PaddingStyle.Iso7816:
                    return UnpadIso7816(data, blockSize);
                case PaddingStyle.Iso10126:
                    return UnpadIso10126(data, blockSize);
                default:
                    throw new InvalidOperationException("Unknown padding style");
            }
        }

        public static byte[] PadPkcs7(byte[] data, int blockSize)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            int paddingLength = blockSize - data.Length % blockSize;

            byte[] paddedData = new byte[data.Length + paddingLength];
            Array.Copy(data, 0, paddedData, 0, data.Length);
            for (int i = data.Length; i < paddedData.Length; i++)
                paddedData[i] = (byte)paddingLength;

            return paddedData;
        }

        public static byte[] UnpadPkcs7(byte[] data, int blockSize)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            if (data.Length % blockSize != 0 || data.Length == 0)
                throw new PaddingException("Data is not padded");

            byte paddingLength = data[data.Length - 1];

            for (int i = data.Length - 2; i > data.Length - paddingLength - 1; i--)
            {
                if (data[i] != paddingLength)
                    throw new PaddingException("Invalid Pkcs7 padding");
            }

            byte[] unpaddedData = new byte[data.Length - paddingLength];
            Array.Copy(data, 0, unpaddedData, 0, data.Length - paddingLength);

            return unpaddedData;
        }

        public static byte[] PadAnsiX923(byte[] data, int blockSize)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            int paddingLength = blockSize - data.Length % blockSize;

            byte[] paddedData = new byte[data.Length + paddingLength];
            Array.Copy(data, 0, paddedData, 0, data.Length);
            for (int i = data.Length; i < paddedData.Length - 1; i++)
                paddedData[i] = 0;
            paddedData[paddedData.Length - 1] = (byte)paddingLength;

            return paddedData;
        }

        public static byte[] UnpadAnsiX923(byte[] data, int blockSize)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            if (data.Length % blockSize != 0 || data.Length == 0)
                throw new PaddingException("Data is not padded");

            byte paddingLength = data[data.Length - 1];

            for (int i = data.Length - 2; i > data.Length - paddingLength - 1; i--)
            {
                if (data[i] != 0)
                    throw new PaddingException("Invalid AnsiX923 padding");
            }

            byte[] unpaddedData = new byte[data.Length - paddingLength];
            Array.Copy(data, 0, unpaddedData, 0, data.Length - paddingLength);

            return unpaddedData;
        }

        public static byte[] PadIso7816(byte[] data, int blockSize)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            int paddingLength = blockSize - data.Length % blockSize;

            byte[] paddedData = new byte[data.Length + paddingLength];
            Array.Copy(data, 0, paddedData, 0, data.Length);

            paddedData[data.Length] = 0x80;

            for (int i = data.Length + 1; i < paddedData.Length; i++)
                paddedData[i] = 0;

            return paddedData;
        }

        public static byte[] UnpadIso7816(byte[] data, int blockSize)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            if (data.Length % blockSize != 0 || data.Length == 0)
                throw new PaddingException("Data is not padded");

            int unpadLength;
            for (unpadLength = data.Length - 1; unpadLength >= 0; unpadLength--)
                if (data[unpadLength] == 0x80)
                    break;

            if (unpadLength == 0)
                throw new PaddingException("Invalid Iso7816 padding");

            byte[] unpaddedData = new byte[unpadLength];
            Array.Copy(data, 0, unpaddedData, 0, unpadLength);

            return unpaddedData;
        }

        public static byte[] PadIso10126(byte[] data, int blockSize)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            int paddingLength = blockSize - data.Length % blockSize;

            byte[] paddedData = new byte[data.Length + paddingLength];
            Array.Copy(data, 0, paddedData, 0, data.Length);
            byte[] rndBytes = RandomHelper.GenerateBytes(paddingLength - 1);
            Array.Copy(rndBytes, 0, paddedData, data.Length, paddingLength - 1);
            paddedData[paddedData.Length - 1] = (byte)paddingLength;

            return paddedData;
        }

        public static byte[] UnpadIso10126(byte[] data, int blockSize)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            if (data.Length % blockSize != 0 || data.Length == 0)
                throw new PaddingException("Data is not padded");

            byte paddingLength = data[data.Length - 1];

            byte[] unpaddedData = new byte[data.Length - paddingLength];
            Array.Copy(data, 0, unpaddedData, 0, data.Length - paddingLength);

            return unpaddedData;
        }
    }
}
