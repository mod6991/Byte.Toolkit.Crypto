using Org.BouncyCastle.Crypto.Digests;

namespace Byte.Toolkit.Crypto.Hash
{
    public static class SHA3
    {
        /// <summary>
        /// Hash data with SHA3
        /// </summary>
        /// <param name="data">Data to hash</param>
        /// <param name="bitLength">Size in bits</param>
        /// <returns>Hash</returns>
        public static byte[] Hash(byte[] data, int bitLength = 512)
        {
            byte[] result = new byte[bitLength / 8];

            Sha3Digest sha3 = new Sha3Digest(bitLength);
            sha3.BlockUpdate(data, 0, data.Length);
            sha3.DoFinal(result, 0);

            return result;
        }

        /// <summary>
        /// Hash stream with SHA3
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="bitLength">Size in bits</param>
        /// <param name="bufferSize">Buffer size</param>
        /// <returns>Hash</returns>
        public static byte[] Hash(Stream input, int bitLength = 512, int bufferSize = 4096)
        {
            byte[] result = new byte[bitLength / 8];

            Sha3Digest sha3 = new Sha3Digest(bitLength);
            int bytesRead;
            byte[] buffer = new byte[bufferSize];

            do
            {
                bytesRead = input.Read(buffer, 0, bufferSize);
                if (bytesRead > 0)
                    sha3.BlockUpdate(buffer, 0, bytesRead);
            } while (bytesRead == bufferSize);


            sha3.DoFinal(result, 0);

            return result;
        }
    }
}
