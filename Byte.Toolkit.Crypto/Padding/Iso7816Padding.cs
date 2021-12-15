using System;

namespace Byte.Toolkit.Crypto.Padding
{
    public sealed class Iso7816Padding : IDataPadding
    {
        /// <summary>
        /// Pad data with ISO/IEC 7816-4
        /// </summary>
        /// <param name="data">Data to pad</param>
        /// <param name="blockSize">Block size</param>
        /// <returns>Padded data</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public byte[] Pad(byte[] data, int blockSize)
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

        /// <summary>
        /// Unpad data with ISO/IEC 7816-4
        /// </summary>
        /// <param name="paddedData">Data to unpad</param>
        /// <param name="blockSize">Block size</param>
        /// <returns>Unpadded data</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="PaddingException"></exception>
        public byte[] UnPad(byte[] paddedData, int blockSize)
        {
            if (paddedData == null)
                throw new ArgumentNullException("paddedData");

            if (paddedData.Length % blockSize != 0 || paddedData.Length == 0)
                throw new PaddingException("Data is not padded");

            int unpadLength;
            for (unpadLength = paddedData.Length - 1; unpadLength >= 0; unpadLength--)
                if (paddedData[unpadLength] == 0x80)
                    break;

            if (unpadLength == 0)
                throw new PaddingException("Invalid Iso7816 padding");

            byte[] unpaddedData = new byte[unpadLength];
            Array.Copy(paddedData, 0, unpaddedData, 0, unpadLength);

            return unpaddedData;
        }
    }
}
