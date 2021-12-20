using Byte.Toolkit.Crypto.IO;
using Byte.Toolkit.Crypto.KDF;
using Byte.Toolkit.Crypto.Padding;
using Byte.Toolkit.Crypto.Random;
using Byte.Toolkit.Crypto.SymKey;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Byte.Toolkit.Crypto.FileEnc
{
    public static class AesFileEnc
    {
        private const byte _version = 0x04;

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
