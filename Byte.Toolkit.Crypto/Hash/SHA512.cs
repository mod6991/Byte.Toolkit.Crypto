using Org.BouncyCastle.Crypto.Digests;
using System.IO;

namespace Byte.Toolkit.Crypto.Hash
{
    public static class SHA512
    {
        /// <summary>
        /// Hash data with SHA512
        /// </summary>
        /// <param name="data">Data to hash</param>
        /// <returns>Hash</returns>
        public static byte[] Hash(byte[] data)
        {
            byte[] result = new byte[64];

            Sha512Digest sha512 = new Sha512Digest();
            sha512.BlockUpdate(data, 0, data.Length);
            sha512.DoFinal(result, 0);

            return result;
        }

        /// <summary>
        /// Hash stream with SHA512
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="bufferSize">Buffer size</param>
        /// <returns>Hash</returns>
        public static byte[] Hash(Stream input, int bufferSize = 4096)
        {
            byte[] result = new byte[64];

            Sha512Digest sha512 = new Sha512Digest();
            int bytesRead;
            byte[] buffer = new byte[bufferSize];

            do
            {
                bytesRead = input.Read(buffer, 0, bufferSize);
                if (bytesRead > 0)
                    sha512.BlockUpdate(buffer, 0, bytesRead);
            } while (bytesRead == bufferSize);


            sha512.DoFinal(result, 0);

            return result;
        }

        /// <summary>
        /// Hash file with SHA512
        /// </summary>
        /// <param name="filePath">File path</param>
        /// <param name="bufferSize">Buffer size</param>
        /// <returns>Hash</returns>
        public static byte[] Hash(string filePath, int bufferSize = 4096)
        {
            using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                return Hash(fs, bufferSize);
            }
        }
    }
}
