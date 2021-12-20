using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Byte.Toolkit.Crypto.IO;
using Byte.Toolkit.Crypto.PubKey;
using Byte.Toolkit.Crypto.Random;
using Byte.Toolkit.Crypto.SymKey;
using NUnit.Framework;

namespace CryptoToolkitUnitTests.FileEnc
{
    public class ChaChaAesFileEncTests
    {
        public void EncryptDecrypt(Tuple<string, string, string, string> values)
        {
            Assert.Multiple(() =>
            {
                for (int i = 0; i < 10; i++)
                {
                    //var rsa = RSA.GenerateKeyPair(2048);
                    //byte[] data
                }
            });
        }
    }
}
