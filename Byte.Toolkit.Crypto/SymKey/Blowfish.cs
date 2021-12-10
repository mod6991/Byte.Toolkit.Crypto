﻿using Byte.Toolkit.Crypto.Padding;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Byte.Toolkit.Crypto.SymKey
{
    public static class Blowfish
    {
        public const int KEY_SIZE = 56;
        public const int IV_SIZE = 8;
        public const int BLOCK_SIZE = 8;

        /// <summary>
        /// Encrypt data with Blowfish-CBC
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <param name="key">Key</param>
        /// <param name="iv">IV</param>
        /// <returns>Encrypted data</returns>
        public static byte[] EncryptCBC(byte[] data, byte[] key, byte[] iv)
        {
            byte[] enc = new byte[data.Length];

            IBufferedCipher cipher = new BufferedBlockCipher(new CbcBlockCipher(new BlowfishEngine()));
            ParametersWithIV parameters = new ParametersWithIV(new KeyParameter(key, 0, key.Length), iv, 0, iv.Length);
            cipher.Init(true, parameters);
            cipher.ProcessBytes(data, enc, 0);

            return enc;
        }

        /// <summary>
        /// Encrypt stream with Blowfish-CBC
        /// </summary>
        /// <param name="input">Input stream to encrypt</param>
        /// <param name="output">Output stream</param>
        /// <param name="key">Key</param>
        /// <param name="iv">IV</param>
        /// <param name="paddingStyle">Padding</param>
        /// <param name="notifyProgression">Notify progression method</param>
        /// <param name="bufferSize">Buffer size</param>
        public static void EncryptCBC(Stream input, Stream output, byte[] key, byte[] iv, PaddingStyle paddingStyle = PaddingStyle.Pkcs7, Action<int> notifyProgression = null, int bufferSize = 4096)
        {
            IBufferedCipher cipher = new BufferedBlockCipher(new CbcBlockCipher(new BlowfishEngine()));
            ParametersWithIV parameters = new ParametersWithIV(new KeyParameter(key, 0, key.Length), iv, 0, iv.Length);
            cipher.Init(true, parameters);

            bool padDone = false;
            int bytesRead;
            byte[] buffer = new byte[bufferSize];
            byte[] enc = new byte[bufferSize];

            do
            {
                bytesRead = input.Read(buffer, 0, bufferSize);

                if (bytesRead == bufferSize)
                {
                    cipher.ProcessBytes(buffer, enc, 0);
                    output.Write(enc, 0, bytesRead);
                }
                else if (bytesRead > 0)
                {
                    byte[] smallBuffer = new byte[bytesRead];
                    Array.Copy(buffer, 0, smallBuffer, 0, bytesRead);
                    byte[] padData = Padding.Padding.Pad(smallBuffer, BLOCK_SIZE, paddingStyle);
                    cipher.ProcessBytes(padData, enc, 0);
                    output.Write(enc, 0, padData.Length);
                    padDone = true;
                }

                if (notifyProgression != null && bytesRead > 0)
                    notifyProgression(bytesRead);
            } while (bytesRead == bufferSize);

            if (!padDone)
            {
                buffer = new byte[0];
                byte[] padData = Padding.Padding.Pad(buffer, BLOCK_SIZE, paddingStyle);
                cipher.ProcessBytes(padData, enc, 0);
                output.Write(enc, 0, padData.Length);
            }
        }

        /// <summary>
        /// Decrypt data with Blowfish-CBC
        /// </summary>
        /// <param name="data">Data to decrypt</param>
        /// <param name="key">Key</param>
        /// <param name="iv">IV</param>
        /// <returns>Decrypted data</returns>
        public static byte[] DecryptCBC(byte[] data, byte[] key, byte[] iv)
        {
            byte[] dec = new byte[data.Length];

            IBufferedCipher cipher = new BufferedBlockCipher(new CbcBlockCipher(new BlowfishEngine()));
            ParametersWithIV parameters = new ParametersWithIV(new KeyParameter(key, 0, key.Length), iv, 0, iv.Length);
            cipher.Init(false, parameters);
            cipher.ProcessBytes(data, dec, 0);

            return dec;
        }

        /// <summary>
        /// Decrypt stream with Blowfish-CBC
        /// </summary>
        /// <param name="input">Input stream to decrypt</param>
        /// <param name="output">Output stream</param>
        /// <param name="key">Key</param>
        /// <param name="iv">IV</param>
        /// <param name="paddingStyle">Padding</param>
        /// <param name="notifyProgression">Notify progression method</param>
        /// <param name="bufferSize">Buffer size</param>
        public static void DecryptCBC(Stream input, Stream output, byte[] key, byte[] iv, PaddingStyle paddingStyle = PaddingStyle.Pkcs7, Action<int> notifyProgression = null, int bufferSize = 4096)
        {
            IBufferedCipher cipher = new BufferedBlockCipher(new CbcBlockCipher(new BlowfishEngine()));
            ParametersWithIV parameters = new ParametersWithIV(new KeyParameter(key, 0, key.Length), iv, 0, iv.Length);
            cipher.Init(false, parameters);

            byte[] backup = null;
            int bytesRead;
            byte[] buffer = new byte[bufferSize];
            byte[] dec = new byte[bufferSize];

            do
            {
                bytesRead = input.Read(buffer, 0, bufferSize);

                if (bytesRead > 0)
                {
                    if (backup != null)
                    {
                        output.Write(backup, 0, backup.Length);
                        backup = null;
                    }

                    if (bytesRead == bufferSize)
                    {
                        cipher.ProcessBytes(buffer, dec, 0);
                        backup = new byte[bytesRead];
                        Array.Copy(dec, 0, backup, 0, bytesRead);
                    }
                    else
                    {
                        dec = new byte[bytesRead];
                        byte[] smallBuffer = new byte[bytesRead];
                        Array.Copy(buffer, 0, smallBuffer, 0, bytesRead);
                        cipher.ProcessBytes(smallBuffer, dec, 0);
                        byte[] unpadData = Padding.Padding.Unpad(dec, BLOCK_SIZE, paddingStyle);
                        output.Write(unpadData, 0, unpadData.Length);
                    }

                    if (notifyProgression != null)
                        notifyProgression(bytesRead);
                }
                else
                {
                    if (backup != null)
                    {
                        byte[] unpadData = Padding.Padding.Unpad(backup, BLOCK_SIZE, paddingStyle);
                        output.Write(unpadData, 0, unpadData.Length);
                    }
                }
            } while (bytesRead == bufferSize);
        }
    }
}
