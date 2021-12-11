namespace Byte.Toolkit.Crypto.Padding
{
    public interface IDataPadding
    {
        /// <summary>
        /// Pad data
        /// </summary>
        /// <param name="data">Data to pad</param>
        /// <param name="blockSize">Block size</param>
        /// <returns>Padded data</returns>
        byte[] Pad(byte[] data, int blockSize);

        /// <summary>
        /// Unpad data
        /// </summary>
        /// <param name="paddedData">Data to unpad</param>
        /// <param name="blockSize">Block size</param>
        /// <returns>Unpadded data</returns>
        byte[] UnPad(byte[] paddedData, int blockSize);
    }

    public class PaddingException : Exception
    {
        public PaddingException(string message) : base(message) { }
    }
}
