namespace Byte.Toolkit.Crypto.Padding
{
    /// <summary>
    /// No padding class using IDataPadding
    /// </summary>
    public sealed class NoPadding : IDataPadding
    {
        /// <summary>
        /// Only returns the input data
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="blockSize">Block size</param>
        /// <returns>Original data</returns>
        public byte[] Pad(byte[] data, int blockSize)
        {
            return data;
        }

        /// <summary>
        /// Only returns the input data
        /// </summary>
        /// <param name="paddedData">Data</param>
        /// <param name="blockSize">Block size</param>
        /// <returns>Original data</returns>
        public byte[] UnPad(byte[] paddedData, int blockSize)
        {
            return paddedData;
        }
    }
}
