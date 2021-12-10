using Org.BouncyCastle.Crypto.Digests;

namespace Byte.Toolkit.Crypto.Hash
{
    public static class MD5
    {
        /// <summary>
        /// Hash data with MD5
        /// </summary>
        /// <param name="data">Data to hash</param>
        /// <returns>Hash</returns>
        public static byte[] Hash(byte[] data)
        {
            byte[] result = new byte[16];

            MD5Digest md5 = new MD5Digest();
            md5.BlockUpdate(data, 0, data.Length);
            md5.DoFinal(result, 0);

            return result;
        }

        /// <summary>
        /// Hash stream with MD5
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="bufferSize">Buffer size</param>
        /// <returns>Hash</returns>
        public static byte[] Hash(Stream input, int bufferSize = 4096)
        {
            byte[] result = new byte[16];

            MD5Digest md5 = new MD5Digest();
            int bytesRead;
            byte[] buffer = new byte[bufferSize];

            do
            {
                bytesRead = input.Read(buffer, 0, bufferSize);
                if (bytesRead > 0)
                    md5.BlockUpdate(buffer, 0, bytesRead);
            } while (bytesRead == bufferSize);


            md5.DoFinal(result, 0);

            return result;
        }
    }
}
