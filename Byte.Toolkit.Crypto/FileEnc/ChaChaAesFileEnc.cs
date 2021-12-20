using Byte.Toolkit.Crypto.IO;
using Byte.Toolkit.Crypto.Padding;
using Byte.Toolkit.Crypto.Random;
using Byte.Toolkit.Crypto.SymKey;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Byte.Toolkit.Crypto.FileEnc
{
    /// <summary>
    /// Encrypt/Decrypt files with ChaCha20Rfc7539 and AES-256 (with RSA key or password)
    /// </summary>
    public static class ChaChaAesFileEnc
    {
        private const byte _version = 0x04;
        private const int _bufferSize = 4096;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="input"></param>
        /// <param name="output"></param>
        /// <param name="rsa"></param>
        /// <param name="keyName"></param>
        /// <param name="notifyProgression"></param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void Encrypt(Stream input, Stream output, RSACryptoServiceProvider rsa, string keyName, Action<int> notifyProgression = null)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));
            if (output == null)
                throw new ArgumentNullException(nameof(output));
            if (rsa == null)
                throw new ArgumentNullException(nameof(rsa));
            if (keyName == null)
                throw new ArgumentNullException(nameof(keyName));

            IDataPadding padding = new Pkcs7Padding();

            byte[] key1 = RandomHelper.GenerateBytes(ChaCha20Rfc7539.KEY_SIZE);
            byte[] iv1 = RandomHelper.GenerateBytes(ChaCha20Rfc7539.NONCE_SIZE);
            byte[] key2 = RandomHelper.GenerateBytes(AES.KEY_SIZE);
            byte[] iv2 = RandomHelper.GenerateBytes(AES.IV_SIZE);

            byte[] keysData;
            using (MemoryStream ms = new MemoryStream())
            {
                BinaryHelper.WriteLV(ms, key1);
                BinaryHelper.WriteLV(ms, iv1);
                BinaryHelper.WriteLV(ms, key2);
                BinaryHelper.WriteLV(ms, iv2);
                keysData = ms.ToArray();
            }

            byte[] encKeysData = PubKey.RSA.Encrypt(rsa, keysData);

            BinaryHelper.Write(output, "ENCR!", Encoding.ASCII);
            BinaryHelper.Write(output, _version);
            BinaryHelper.WriteLV(output, Encoding.ASCII.GetBytes(keyName));
            BinaryHelper.WriteLV(output, encKeysData);

            bool padDone = false;
            int bytesRead;
            byte[] buffer = new byte[_bufferSize];

            do
            {
                bytesRead = input.Read(buffer, 0, _bufferSize);

                if (bytesRead > 0)
                {
                    if (bytesRead == _bufferSize)
                    {
                        XorEncryptAndWrite(output, bytesRead, buffer, key1, iv1, key2, iv2);
                    }
                    else
                    {
                        byte[] smallBuffer = new byte[bytesRead];
                        Array.Copy(buffer, 0, smallBuffer, 0, bytesRead);
                        byte[] padData = padding.Pad(smallBuffer, AES.BLOCK_SIZE);
                        padDone = true;

                        XorEncryptAndWrite(output, padData.Length, padData, key1, iv1, key2, iv2);
                    }

                    if (notifyProgression != null)
                        notifyProgression(bytesRead);
                }
            } while (bytesRead == _bufferSize);

            if (!padDone)
            {
                buffer = new byte[0];
                byte[] padData = padding.Pad(buffer, AES.BLOCK_SIZE);

                XorEncryptAndWrite(output, AES.BLOCK_SIZE, padData, key1, iv1, key2, iv2);
            }

            BinaryHelper.WriteLV(output, new byte[0]);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="inputFile"></param>
        /// <param name="outputFile"></param>
        /// <param name="rsa"></param>
        /// <param name="keyName"></param>
        /// <param name="notifyProgression"></param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void Encrypt(string inputFile, string outputFile, RSACryptoServiceProvider rsa, string keyName, Action<int> notifyProgression = null)
        {
            if (inputFile == null)
                throw new ArgumentNullException(nameof(inputFile));
            if (outputFile == null)
                throw new ArgumentNullException(nameof(outputFile));
            if (rsa == null)
                throw new ArgumentNullException(nameof(rsa));
            if (keyName == null)
                throw new ArgumentNullException(nameof(keyName));

            using (FileStream fsIn = StreamHelper.GetFileStreamOpen(inputFile))
            {
                using (FileStream fsOut = StreamHelper.GetFileStreamCreate(outputFile))
                {
                    Encrypt(fsIn, fsOut, rsa, keyName, notifyProgression);
                }
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="input"></param>
        /// <param name="output"></param>
        /// <param name="password"></param>
        /// <param name="notifyProgression"></param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void Encrypt(Stream input, Stream output, string password, Action<int> notifyProgression = null)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));
            if (output == null)
                throw new ArgumentNullException(nameof(output));
            if (password == null)
                throw new ArgumentNullException(nameof(password));

            //TODO!
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="inputFile"></param>
        /// <param name="outputFile"></param>
        /// <param name="password"></param>
        /// <param name="notifyProgression"></param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void Encrypt(string inputFile, string outputFile, string password, Action<int> notifyProgression = null)
        {
            if (inputFile == null)
                throw new ArgumentNullException(nameof(inputFile));
            if (outputFile == null)
                throw new ArgumentNullException(nameof(outputFile));
            if (password == null)
                throw new ArgumentNullException(nameof(password));

            using (FileStream fsIn = StreamHelper.GetFileStreamOpen(inputFile))
            {
                using (FileStream fsOut = StreamHelper.GetFileStreamCreate(outputFile))
                {
                    Encrypt(fsIn, fsOut, password, notifyProgression);
                }
            }
        }

        public static void Decrypt(Stream input, Stream output, RSACryptoServiceProvider rsa, Action<int> notifyProgression = null)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));
            if (output == null)
                throw new ArgumentNullException(nameof(output));
            if (rsa == null)
                throw new ArgumentNullException(nameof(rsa));

            IDataPadding padding = new Pkcs7Padding();

            input.Seek(5, SeekOrigin.Current); // Header
            input.Seek(1, SeekOrigin.Current); // Version

            byte[] keyNameData = BinaryHelper.ReadLV(input);
            byte[] encKeysData = BinaryHelper.ReadLV(input);

            if (notifyProgression != null)
                notifyProgression(5 + 1 + 2 * 4 + keyNameData.Length + encKeysData.Length);

            byte[] keysData = PubKey.RSA.Decrypt(rsa, encKeysData);

            byte[] key1, iv1, key2, iv2;
            using (MemoryStream ms = new MemoryStream(keysData))
            {
                key1 = BinaryHelper.ReadLV(ms);
                iv1 = BinaryHelper.ReadLV(ms);
                key2 = BinaryHelper.ReadLV(ms);
                iv2 = BinaryHelper.ReadLV(ms);
            }

            byte[] d1, d2;
            byte[] backup = null;

            do
            {
                d1 = BinaryHelper.ReadLV(input);
                if (d1.Length > 0)
                {
                    if (backup != null)
                        output.Write(backup, 0, backup.Length);

                    byte[] rpad = ChaCha20Rfc7539.Decrypt(d1, key1, iv1);
                    d2 = BinaryHelper.ReadLV(input);
                    byte[] xor = AES.DecryptCBC(d2, key2, iv2);

                    if (notifyProgression != null)
                        notifyProgression(2 * 4 + d1.Length + d2.Length);

                    byte[] data = new byte[rpad.Length];
                    for (int i = 0; i < rpad.Length; i++)
                        data[i] = (byte)(rpad[i] ^ xor[i]);

                    backup = new byte[data.Length];
                    Array.Copy(data, 0, backup, 0, data.Length);
                }
                else
                {
                    byte[] unpadData = padding.UnPad(backup, AES.BLOCK_SIZE);
                    output.Write(unpadData, 0, unpadData.Length);
                }

            } while (d1.Length > 0);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="inputFile"></param>
        /// <param name="outputFile"></param>
        /// <param name="rsa"></param>
        /// <param name="notifyProgression"></param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void Decrypt(string inputFile, string outputFile, RSACryptoServiceProvider rsa, Action<int> notifyProgression = null)
        {
            if (inputFile == null)
                throw new ArgumentNullException(nameof(inputFile));
            if (outputFile == null)
                throw new ArgumentNullException(nameof(outputFile));
            if (rsa == null)
                throw new ArgumentNullException(nameof(rsa));

            using (FileStream fsIn = StreamHelper.GetFileStreamOpen(inputFile))
            {
                using (FileStream fsOut = StreamHelper.GetFileStreamCreate(outputFile))
                {
                    Decrypt(fsIn, fsOut, rsa, notifyProgression);
                }
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="input"></param>
        /// <param name="output"></param>
        /// <param name="password"></param>
        /// <param name="notifyProgression"></param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void Decrypt(Stream input, Stream output, string password, Action<int> notifyProgression = null)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));
            if (output == null)
                throw new ArgumentNullException(nameof(output));
            if (password == null)
                throw new ArgumentNullException(nameof(password));

            //TODO!
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="inputFile"></param>
        /// <param name="outputFile"></param>
        /// <param name="password"></param>
        /// <param name="notifyProgression"></param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void Decrypt(string inputFile, string outputFile, string password, Action<int> notifyProgression = null)
        {
            if (inputFile == null)
                throw new ArgumentNullException(nameof(inputFile));
            if (outputFile == null)
                throw new ArgumentNullException(nameof(outputFile));
            if (password == null)
                throw new ArgumentNullException(nameof(password));

            using (FileStream fsIn = StreamHelper.GetFileStreamOpen(inputFile))
            {
                using (FileStream fsOut = StreamHelper.GetFileStreamCreate(outputFile))
                {
                    Decrypt(fsIn, fsOut, password, notifyProgression);
                }
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="output"></param>
        /// <param name="size"></param>
        /// <param name="data"></param>
        /// <param name="key1"></param>
        /// <param name="iv1"></param>
        /// <param name="key2"></param>
        /// <param name="iv2"></param>
        private static void XorEncryptAndWrite(Stream output, int size, byte[] data, byte[] key1, byte[] iv1, byte[] key2, byte[] iv2)
        {
            byte[] rpad = RandomHelper.GenerateBytes(size);
            byte[] xor = new byte[size];

            for (int i = 0; i < size; i++)
                xor[i] = (byte)(data[i] ^ rpad[i]);

            byte[] d1 = ChaCha20Rfc7539.Encrypt(rpad, key1, iv1);
            byte[] d2 = AES.EncryptCBC(xor, key2, iv2);

            BinaryHelper.WriteLV(output, d1);
            BinaryHelper.WriteLV(output, d2);
        }
    }
}
