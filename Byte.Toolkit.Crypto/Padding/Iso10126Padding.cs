using Byte.Toolkit.Crypto.Random;

namespace Byte.Toolkit.Crypto.Padding
{
    public class Iso10126Padding : IDataPadding
    {
        /// <summary>
        /// Pad data with ISO 10126
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
            byte[] rndBytes = RandomHelper.GenerateBytes(paddingLength - 1);
            Array.Copy(rndBytes, 0, paddedData, data.Length, paddingLength - 1);
            paddedData[paddedData.Length - 1] = (byte)paddingLength;

            return paddedData;
        }

        /// <summary>
        /// Unpad data with ISO 10126
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

            byte paddingLength = paddedData[paddedData.Length - 1];

            byte[] unpaddedData = new byte[paddedData.Length - paddingLength];
            Array.Copy(paddedData, 0, unpaddedData, 0, paddedData.Length - paddingLength);

            return unpaddedData;
        }
    }
}
