﻿using Byte.Toolkit.Crypto.IO;
using Org.BouncyCastle.Crypto.Digests;
using System;
using System.IO;

namespace Byte.Toolkit.Crypto.Hash
{
    /// <summary>
    /// Hash data with SHA1
    /// </summary>
    public static class SHA1
    {
        /// <summary>
        /// SHA1 hash size
        /// </summary>
        public const int HASH_SIZE = 20;

        /// <summary>
        /// Hash data with SHA1
        /// </summary>
        /// <param name="data">Data to hash</param>
        /// <returns>SHA1 hash</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] Hash(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            byte[] result = new byte[HASH_SIZE];

            Sha1Digest sha1 = new Sha1Digest();
            sha1.BlockUpdate(data, 0, data.Length);
            sha1.DoFinal(result, 0);

            return result;
        }

        /// <summary>
        /// Hash data from stream with SHA1
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="bufferSize">Buffer size</param>
        /// <returns>SHA1 hash</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] Hash(Stream input, int bufferSize = 4096)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));

            byte[] result = new byte[HASH_SIZE];

            Sha1Digest sha1 = new Sha1Digest();
            int bytesRead;
            byte[] buffer = new byte[bufferSize];

            do
            {
                bytesRead = input.Read(buffer, 0, bufferSize);
                if (bytesRead > 0)
                    sha1.BlockUpdate(buffer, 0, bytesRead);
            } while (bytesRead == bufferSize);


            sha1.DoFinal(result, 0);

            return result;
        }

        /// <summary>
        /// Hash file with SHA1
        /// </summary>
        /// <param name="inputFile">File to hash</param>
        /// <param name="bufferSize">Buffer size</param>
        /// <returns>SHA1 hash</returns>
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
