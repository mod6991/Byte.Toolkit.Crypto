﻿using Byte.Toolkit.Crypto.IO;
using Org.BouncyCastle.Crypto.Digests;
using System;
using System.IO;
using System.Threading.Tasks;

namespace Byte.Toolkit.Crypto.Hash
{
    /// <summary>
    /// Hash data with SHA512
    /// </summary>
    public static class SHA512
    {
        /// <summary>
        /// SHA512 hash size
        /// </summary>
        public const int HASH_SIZE = 64;

        /// <summary>
        /// Hash data with SHA512
        /// </summary>
        /// <param name="data">Data to hash</param>
        /// <returns>SHA512 hash</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] Hash(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            byte[] result = new byte[HASH_SIZE];

            Sha512Digest sha512 = new Sha512Digest();
            sha512.BlockUpdate(data, 0, data.Length);
            sha512.DoFinal(result, 0);

            return result;
        }

        /// <summary>
        /// Hash data from stream with SHA512
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="bufferSize">Buffer size</param>
        /// <returns>SHA512 hash</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] Hash(Stream input, int bufferSize = 4096)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));

            byte[] result = new byte[HASH_SIZE];

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
        /// Asynchronously hash data from stream with SHA512
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="bufferSize">Buffer size</param>
        /// <returns>SHA512 hash</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static async Task<byte[]> HashAsync(Stream input, int bufferSize = 4096)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));

            byte[] result = new byte[HASH_SIZE];

            Sha512Digest sha512 = new Sha512Digest();
            int bytesRead;
            byte[] buffer = new byte[bufferSize];

            do
            {
                bytesRead = await input.ReadAsync(buffer, 0, bufferSize).ConfigureAwait(false);
                if (bytesRead > 0)
                    sha512.BlockUpdate(buffer, 0, bytesRead);
            } while (bytesRead == bufferSize);


            sha512.DoFinal(result, 0);

            return result;
        }

        /// <summary>
        /// Hash file with SHA512
        /// </summary>
        /// <param name="inputFile">File to hash</param>
        /// <param name="bufferSize">Buffer size</param>
        /// <returns>SHA512 hash</returns>
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

        /// <summary>
        /// Asynchronously hash file with SHA512
        /// </summary>
        /// <param name="inputFile">File to hash</param>
        /// <param name="bufferSize">Buffer size</param>
        /// <returns>SHA512 hash</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static async Task<byte[]> HashAsync(string inputFile, int bufferSize = 4096)
        {
            if (inputFile == null)
                throw new ArgumentNullException(nameof(inputFile));

            using (FileStream fs = StreamHelper.GetFileStreamOpen(inputFile))
            {
                return await HashAsync(fs, bufferSize).ConfigureAwait(false);
            }
        }
    }
}
