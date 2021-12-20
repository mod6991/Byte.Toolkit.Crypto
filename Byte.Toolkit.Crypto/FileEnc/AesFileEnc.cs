using Byte.Toolkit.Crypto.IO;
using Byte.Toolkit.Crypto.KDF;
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
    /// Encrypt/Decrypt files with AES-256-CBC with RSA key or password
    /// </summary>
    public static class AesFileEnc
    {
        private const byte _version = 0x04;

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

            //TODO!
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

        /// <summary>
        /// 
        /// </summary>
        /// <param name="input"></param>
        /// <param name="output"></param>
        /// <param name="rsa"></param>
        /// <param name="notifyProgression"></param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void Decrypt(Stream input, Stream output, RSACryptoServiceProvider rsa, Action<int> notifyProgression = null)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));
            if (output == null)
                throw new ArgumentNullException(nameof(output));
            if (rsa == null)
                throw new ArgumentNullException(nameof(rsa));

            //TODO!
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
    }
}
