﻿using System;

namespace Byte.Toolkit.Crypto.Padding
{
    /// <summary>
    /// Pad and unpad data with ANSI X9.23
    /// </summary>
    public sealed class AnsiX923Padding : IDataPadding
    {
        /// <summary>
        /// Pad data with ANSI X9.23
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
                throw new ArgumentException("Invalid block size", nameof(blockSize));

            int paddingLength = blockSize - data.Length % blockSize;
            byte[] paddedData = new byte[data.Length + paddingLength];
            Array.Copy(data, 0, paddedData, 0, data.Length);
            
            for (int i = data.Length; i < paddedData.Length - 1; i++)
                paddedData[i] = 0;

            paddedData[paddedData.Length - 1] = (byte)paddingLength;

            return paddedData;
        }

        /// <summary>
        /// Unpad data with ANSI X9.23
        /// </summary>
        /// <param name="paddedData">Data to unpad</param>
        /// <param name="blockSize">Block size</param>
        /// <returns>Unpadded data</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="PaddingException"></exception>
        public byte[] UnPad(byte[] paddedData, int blockSize)
        {
            if (paddedData == null)
                throw new ArgumentNullException(nameof(paddedData));
            if (blockSize < 1 || blockSize > byte.MaxValue)
                throw new ArgumentException("Invalid block size", nameof(blockSize));
            if (paddedData.Length % blockSize != 0 || paddedData.Length < blockSize)
                throw new PaddingException("Invalid pad length");

            int dataSize = paddedData.Length - paddedData[paddedData.Length - 1];

            byte[] unpaddedData = new byte[dataSize];
            Array.Copy(paddedData, 0, unpaddedData, 0, dataSize);

            return unpaddedData;
        }
    }
}
