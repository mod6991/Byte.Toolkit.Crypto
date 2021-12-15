using Byte.Toolkit.Crypto.Padding;
using Org.BouncyCastle.Crypto;
using System;
using System.IO;

namespace Byte.Toolkit.Crypto.SymKey
{
    internal static class SymKeyHelper
    {
        /// <summary>
        /// Encrypt stream with cipher in CBC mode
        /// </summary>
        /// <param name="input">Input stream to encrypt</param>
        /// <param name="output">Output stream</param>
        /// <param name="cipher">Cipher</param>
        /// <param name="blockSize">Block size</param>
        /// <param name="padding">Padding</param>
        /// <param name="notifyProgression">Notify progression method</param>
        /// <param name="bufferSize">Buffer size</param>
        public static void EncryptCBC(Stream input, Stream output, IBufferedCipher cipher, int blockSize,
                                      IDataPadding padding, Action<int> notifyProgression, int bufferSize)
        {
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
                    byte[] padData = padding.Pad(smallBuffer, blockSize);
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
                byte[] padData = padding.Pad(buffer, blockSize);
                cipher.ProcessBytes(padData, enc, 0);
                output.Write(enc, 0, padData.Length);
            }
        }

        /// <summary>
        /// Decrypt stream with cipher in CBC mode
        /// </summary>
        /// <param name="input">Input stream to decrypt</param>
        /// <param name="output">Output stream</param>
        /// <param name="cipher">Cipher</param>
        /// <param name="blockSize">Block size</param>
        /// <param name="padding">Padding</param>
        /// <param name="notifyProgression">Notify progression method</param>
        /// <param name="bufferSize">Buffer size</param>
        public static void DecryptCBC(Stream input, Stream output, IBufferedCipher cipher, int blockSize,
                                      IDataPadding padding, Action<int> notifyProgression, int bufferSize)
        {
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
                        byte[] unpadData = padding.UnPad(dec, blockSize);
                        output.Write(unpadData, 0, unpadData.Length);
                    }

                    if (notifyProgression != null)
                        notifyProgression(bytesRead);
                }
                else
                {
                    if (backup != null)
                    {
                        byte[] unpadData = padding.UnPad(backup, blockSize);
                        output.Write(unpadData, 0, unpadData.Length);
                    }
                }
            } while (bytesRead == bufferSize);
        }
    }
}
