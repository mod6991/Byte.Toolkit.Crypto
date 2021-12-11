namespace Byte.Toolkit.Crypto.Padding
{
    public class NoPadding : IDataPadding
    {
        public byte[] Pad(byte[] data, int blockSize)
        {
            return data;
        }

        public byte[] UnPad(byte[] paddedData, int blockSize)
        {
            return paddedData;
        }
    }
}
