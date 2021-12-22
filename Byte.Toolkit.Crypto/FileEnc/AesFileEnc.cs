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
    /// Encrypt/Decrypt files with AES-256 with RSA key or password
    /// </summary>
    public static class AesFileEnc
    {
        private const byte VERSION = 0x05;
        private const int BUFFER_SIZE = 4096;
        private const string RSA_HEADER = "AENCR!";
        private const string PASS_HEADER = "AENCP!";
        private const int SALT_SIZE = 16;

        /// <summary>
        /// Encrypt with AES-256 with a RSA key
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="output">Output stream</param>
        /// <param name="rsa">RSA key</param>
        /// <param name="keyName">Key name</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
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

            byte[] key = RandomHelper.GenerateBytes(AES.KEY_SIZE);
            byte[] iv = RandomHelper.GenerateBytes(AES.IV_SIZE);

            byte[] keyData;
            using (MemoryStream ms = new MemoryStream())
            {
                BinaryHelper.WriteLV(ms, key);
                BinaryHelper.WriteLV(ms, iv);
                keyData = ms.ToArray();
            }

            byte[] encKeyData = PubKey.RSA.Encrypt(rsa, keyData);

            BinaryHelper.Write(output, RSA_HEADER, Encoding.ASCII);
            BinaryHelper.Write(output, VERSION);
            BinaryHelper.WriteLV(output, Encoding.ASCII.GetBytes(keyName));
            BinaryHelper.WriteLV(output, encKeyData);

            AES.EncryptCBC(input, output, key, iv, new Pkcs7Padding(), notifyProgression, BUFFER_SIZE);
        }

        /// <summary>
        /// Encrypt file with AES-256 with a RSA key
        /// </summary>
        /// <param name="inputFile">Input file</param>
        /// <param name="outputFile">Output file</param>
        /// <param name="rsa">RSA key</param>
        /// <param name="keyName">Key name</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
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
        /// Encrypt with AES-256 with a password
        /// </summary>
        /// <param name="input">Input file</param>
        /// <param name="output">Output file</param>
        /// <param name="password">Password</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void Encrypt(Stream input, Stream output, string password, Action<int> notifyProgression = null)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));
            if (output == null)
                throw new ArgumentNullException(nameof(output));
            if (password == null)
                throw new ArgumentNullException(nameof(password));

            byte[] salt = RandomHelper.GenerateBytes(SALT_SIZE);
            byte[] key = PBKDF2.GenerateKeyFromPassword(AES.KEY_SIZE, password, salt);
            byte[] iv = RandomHelper.GenerateBytes(AES.IV_SIZE);

            BinaryHelper.Write(output, PASS_HEADER, Encoding.ASCII);
            BinaryHelper.Write(output, VERSION);
            BinaryHelper.WriteLV(output, salt);
            BinaryHelper.WriteLV(output, iv);

            AES.EncryptCBC(input, output, key, iv, new Pkcs7Padding(), notifyProgression, BUFFER_SIZE);
        }

        /// <summary>
        /// Encrypt file with AES-256 with a password
        /// </summary>
        /// <param name="inputFile">Input file</param>
        /// <param name="outputFile">Output file</param>
        /// <param name="password">Password</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
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
        /// Decrypt with AES-256 with a RSA key
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

            input.Seek(RSA_HEADER.Length, SeekOrigin.Current); // Header
            input.Seek(1, SeekOrigin.Current); // Version

            byte[] keyNameData = BinaryHelper.ReadLV(input);
            byte[] encKeyData = BinaryHelper.ReadLV(input);

            if (notifyProgression != null)
                notifyProgression(RSA_HEADER.Length + 1 + 2 * sizeof(int) + keyNameData.Length + encKeyData.Length);

            byte[] keyData = PubKey.RSA.Decrypt(rsa, encKeyData);

            byte[] key, iv;
            using (MemoryStream ms = new MemoryStream(keyData))
            {
                key = BinaryHelper.ReadLV(ms);
                iv = BinaryHelper.ReadLV(ms);
            }

            AES.DecryptCBC(input, output, key, iv, new Pkcs7Padding(), notifyProgression, BUFFER_SIZE);
        }

        /// <summary>
        /// Decrypt file with AES-256 with a RSA key
        /// </summary>
        /// <param name="inputFile">Input file</param>
        /// <param name="outputFile">Output file</param>
        /// <param name="rsa">RSA key</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
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
        /// Decrypt with AES-256 with a password
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="output">Output stream</param>
        /// <param name="password">Password</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void Decrypt(Stream input, Stream output, string password, Action<int> notifyProgression = null)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));
            if (output == null)
                throw new ArgumentNullException(nameof(output));
            if (password == null)
                throw new ArgumentNullException(nameof(password));

            input.Seek(PASS_HEADER.Length, SeekOrigin.Current); // Header
            input.Seek(1, SeekOrigin.Current); // Version

            byte[] salt = BinaryHelper.ReadLV(input);
            byte[] iv = BinaryHelper.ReadLV(input);

            if (notifyProgression != null)
                notifyProgression(PASS_HEADER.Length + 1 + 2 * sizeof(int) + salt.Length + iv.Length);

            byte[] key = PBKDF2.GenerateKeyFromPassword(AES.KEY_SIZE, password, salt);

            AES.DecryptCBC(input, output, key, iv, new Pkcs7Padding(), notifyProgression);
        }

        /// <summary>
        /// Decrypt file with AES-256 with a password
        /// </summary>
        /// <param name="inputFile">Input file</param>
        /// <param name="outputFile">Output file</param>
        /// <param name="password">Password</param>
        /// <param name="notifyProgression">Notify progression delegate</param>
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