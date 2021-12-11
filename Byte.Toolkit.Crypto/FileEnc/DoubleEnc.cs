using Byte.Toolkit.Crypto.IO;
using Byte.Toolkit.Crypto.KDF;
using Byte.Toolkit.Crypto.Padding;
using Byte.Toolkit.Crypto.Random;
using Byte.Toolkit.Crypto.SymKey;
using System.Security.Cryptography;
using System.Text;

namespace Byte.Toolkit.Crypto.FileEnc
{
    public static class DoubleEnc
    {
        private const byte _version = 0x04;
        private const int _bufferSize = 4096;

        /// <summary>
        /// Encrypt with RSA key
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="output">Output stream</param>
        /// <param name="rsa">RSA key</param>
        /// <param name="keyName">Key name</param>
        /// <param name="notifyProgression">Notify progression method</param>
        public static void EncryptWithKey(Stream input, Stream output, RSACryptoServiceProvider rsa, string keyName, Action<int> notifyProgression = null)
        {
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

        internal static void XorEncryptAndWrite(Stream output, int size, byte[] data, byte[] key1, byte[] iv1, byte[] key2, byte[] iv2)
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

        /// <summary>
        /// Encrypt with password
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="output">Output stream</param>
        /// <param name="password">Password</param>
        /// <param name="notifyProgression">Notify progression method</param>
        public static void EncryptWithPassword(Stream input, Stream output, string password, Action<int> notifyProgression = null)
        {
            IDataPadding padding = new Pkcs7Padding();

            byte[] salt = RandomHelper.GenerateBytes(16);
            byte[] key = PBKDF2.GenerateKeyFromPassword(AES.KEY_SIZE, password, salt);
            byte[] iv = RandomHelper.GenerateBytes(AES.IV_SIZE);

            BinaryHelper.Write(output, "ENCP!", Encoding.ASCII);
            BinaryHelper.Write(output, _version);
            BinaryHelper.Write(output, (byte)iv.Length);
            BinaryHelper.Write(output, (byte)salt.Length);
            BinaryHelper.Write(output, iv);
            BinaryHelper.Write(output, salt);

            AES.EncryptCBC(input, output, key, iv, padding, notifyProgression);
        }

        /// <summary>
        /// Decrypt with RSA key
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="output">Output stream</param>
        /// <param name="rsa">RSA key</param>
        /// <param name="notifyProgression">Notify progression method</param>
        public static void DecryptWithKey(Stream input, Stream output, RSACryptoServiceProvider rsa, Action<int> notifyProgression = null)
        {
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
        /// Decrypt with password
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="output">Output stream</param>
        /// <param name="password">Password</param>
        /// <param name="notifyProgression">Notify progression method</param>
        public static void DecryptWithPassword(Stream input, Stream output, string password, Action<int> notifyProgression = null)
        {
            IDataPadding padding = new Pkcs7Padding();

            input.Seek(5, SeekOrigin.Current); // Header
            input.Seek(1, SeekOrigin.Current); // Version

            byte ivLength = BinaryHelper.ReadByte(input);
            byte saltLength = BinaryHelper.ReadByte(input);
            byte[] iv = BinaryHelper.ReadBytes(input, ivLength);
            byte[] salt = BinaryHelper.ReadBytes(input, saltLength);

            if (notifyProgression != null)
                notifyProgression(5 + 1 + 1 + 1 + ivLength + saltLength);

            byte[] key = PBKDF2.GenerateKeyFromPassword(AES.KEY_SIZE, password, salt);

            AES.DecryptCBC(input, output, key, iv, padding, notifyProgression);
        }
    }
}
