﻿using Byte.Toolkit.Crypto.Padding;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.IO;

namespace Byte.Toolkit.Crypto.SymKey
{
    /// <summary>
    /// Encrypt/Decrypt data with DES
    /// </summary>
    public static class DES
    {
        /// <summary>
        /// DES key size
        /// </summary>
        public const int KEY_SIZE = 8;

        /// <summary>
        /// DES IV size
        /// </summary>
        public const int IV_SIZE = 8;

        /// <summary>
        /// DES block size
        /// </summary>
        public const int BLOCK_SIZE = 8;

        /// <summary>
        /// Encrypt data with DES-CBC
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <param name="key">Key</param>
        /// <param name="iv">IV</param>
        /// <returns>Encrypted data</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] EncryptCBC(byte[] data, byte[] key, byte[] iv)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (iv == null)
                throw new ArgumentNullException(nameof(iv));

            byte[] enc = new byte[data.Length];

            IBufferedCipher cipher = new BufferedBlockCipher(new CbcBlockCipher(new DesEngine()));
            ICipherParameters parameters = new ParametersWithIV(new KeyParameter(key, 0, key.Length), iv, 0, iv.Length);
            cipher.Init(true, parameters);
            cipher.ProcessBytes(data, enc, 0);

            return enc;
        }

        /// <summary>
        /// Encrypt stream with DES-CBC
        /// </summary>
        /// <param name="input">Input stream to encrypt</param>
        /// <param name="output">Output stream</param>
        /// <param name="key">Key</param>
        /// <param name="iv">IV</param>
        /// <param name="padding">Padding</param>
        /// <param name="notifyProgression">Notify progression method</param>
        /// <param name="bufferSize">Buffer size</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void EncryptCBC(Stream input, Stream output, byte[] key, byte[] iv, IDataPadding padding, Action<int> notifyProgression = null, int bufferSize = 4096)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));
            if (output == null)
                throw new ArgumentNullException(nameof(output));
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (iv == null)
                throw new ArgumentNullException(nameof(iv));
            if (padding == null)
                throw new ArgumentNullException(nameof(padding));

            IBufferedCipher cipher = new BufferedBlockCipher(new CbcBlockCipher(new DesEngine()));
            ICipherParameters parameters = new ParametersWithIV(new KeyParameter(key, 0, key.Length), iv, 0, iv.Length);
            cipher.Init(true, parameters);
            SymKeyHelper.EncryptCBC(input, output, cipher, BLOCK_SIZE, padding, notifyProgression, bufferSize);
        }

        /// <summary>
        /// Decrypt data with DES-CBC
        /// </summary>
        /// <param name="data">Data to decrypt</param>
        /// <param name="key">Key</param>
        /// <param name="iv">IV</param>
        /// <returns>Decrypted data</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] DecryptCBC(byte[] data, byte[] key, byte[] iv)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (iv == null)
                throw new ArgumentNullException(nameof(iv));

            byte[] dec = new byte[data.Length];

            IBufferedCipher cipher = new BufferedBlockCipher(new CbcBlockCipher(new DesEngine()));
            ICipherParameters parameters = new ParametersWithIV(new KeyParameter(key, 0, key.Length), iv, 0, iv.Length);
            cipher.Init(false, parameters);
            cipher.ProcessBytes(data, dec, 0);

            return dec;
        }

        /// <summary>
        /// Decrypt stream with DES-CBC
        /// </summary>
        /// <param name="input">Input stream to decrypt</param>
        /// <param name="output">Output stream</param>
        /// <param name="key">Key</param>
        /// <param name="iv">IV</param>
        /// <param name="padding">Padding</param>
        /// <param name="notifyProgression">Notify progression method</param>
        /// <param name="bufferSize">Buffer size</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void DecryptCBC(Stream input, Stream output, byte[] key, byte[] iv, IDataPadding padding, Action<int> notifyProgression = null, int bufferSize = 4096)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));
            if (output == null)
                throw new ArgumentNullException(nameof(output));
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (iv == null)
                throw new ArgumentNullException(nameof(iv));
            if (padding == null)
                throw new ArgumentNullException(nameof(padding));

            IBufferedCipher cipher = new BufferedBlockCipher(new CbcBlockCipher(new DesEngine()));
            ICipherParameters parameters = new ParametersWithIV(new KeyParameter(key, 0, key.Length), iv, 0, iv.Length);
            cipher.Init(false, parameters);
            SymKeyHelper.DecryptCBC(input, output, cipher, BLOCK_SIZE, padding, notifyProgression, bufferSize);
        }
    }
}
