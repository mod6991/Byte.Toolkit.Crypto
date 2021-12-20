using Byte.Toolkit.Crypto.IO;
using Org.BouncyCastle.Crypto.Digests;
using System;
using System.IO;

namespace Byte.Toolkit.Crypto.Hash
{
    /// <summary>
    /// Hash data with MD5
    /// </summary>
    public static class MD5
    {
        /// <summary>
        /// MD5 hash size
        /// </summary>
        public const int HASH_SIZE = 16;

        /// <summary>
        /// Hash data with MD5
        /// </summary>
        /// <param name="data">Data to hash</param>
        /// <returns>MD5 hash</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] Hash(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            byte[] result = new byte[HASH_SIZE];

            MD5Digest md5 = new MD5Digest();
            md5.BlockUpdate(data, 0, data.Length);
            md5.DoFinal(result, 0);

            return result;
        }

        /// <summary>
        /// Hash data from stream with MD5
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="bufferSize">Buffer size</param>
        /// <returns>MD5 hash</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] Hash(Stream input, int bufferSize = 4096)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));

            byte[] result = new byte[HASH_SIZE];

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

        /// <summary>
        /// Hash file with MD5
        /// </summary>
        /// <param name="inputFile">File to hash</param>
        /// <param name="bufferSize">Buffer size</param>
        /// <returns>MD5 hash</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] Hash(string inputFile, int bufferSize = 4096)
        {
            if (inputFile == null)
                throw new ArgumentNullException(nameof(inputFile));

            using (FileStream fs = StreamHelper.GetFileStreamOpen(inputFile))
            {
                return Hash(fs, bufferSize);
            }
        }
    }
}
