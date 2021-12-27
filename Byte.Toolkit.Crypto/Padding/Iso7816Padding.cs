﻿using System;

namespace Byte.Toolkit.Crypto.Padding
{
    /// <summary>
    /// Pad and Unpad data with ISO/IEC 7816-4
    /// </summary>
    public sealed class Iso7816Padding : IDataPadding
    {
        /// <summary>
        /// Pad data with ISO/IEC 7816-4
        /// </summary>
        /// <param name="data">Data to pad</param>
        /// <param name="blockSize">Block size</param>
        /// <returns>Padded data</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        public byte[] Pad(byte[] data, int blockSize)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (blockSize < 1 || blockSize > byte.MaxValue)
                throw new ArgumentException($"Invalid block size {blockSize}", nameof(blockSize));

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
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="PaddingException"></exception>
        public byte[] Unpad(byte[] paddedData, int blockSize)
        {
            if (paddedData == null)
                throw new ArgumentNullException(nameof(paddedData));
            if (blockSize < 1 || blockSize > byte.MaxValue)
                throw new ArgumentException($"Invalid block size {blockSize}", nameof(blockSize));
            if (paddedData.Length % blockSize != 0 || paddedData.Length < blockSize)
                throw new PaddingException($"Invalid padded data length {paddedData.Length}");

            bool foundx80 = false;
            int unpadLength;
            for (unpadLength = paddedData.Length - 1; unpadLength >= paddedData.Length - blockSize; unpadLength--)
            {
                if (paddedData[unpadLength] == 0x80)
                {
                    foundx80 = true;
                    break;
                }
                else
                {
                    if (paddedData[unpadLength] != 0)
                        throw new PaddingException("Invalid Iso7816 padding");
                }
            }

            if (!foundx80)
                throw new PaddingException("Invalid Iso7816 padding");

            byte[] unpaddedData = new byte[unpadLength];
            Array.Copy(paddedData, 0, unpaddedData, 0, unpadLength);

            return unpaddedData;
        }
    }
}
