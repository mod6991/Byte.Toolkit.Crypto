﻿using System;
using System.Collections.Generic;
using System.IO;
using Byte.Toolkit.Crypto.IO;
using Byte.Toolkit.Crypto.Padding;
using Byte.Toolkit.Crypto.SymKey;
using NUnit.Framework;

namespace CryptoToolkitUnitTests.SymKey
{
    public class Salsa20Tests
    {
        static byte[] EmptyArr = new byte[] { };

        [TestCaseSource(nameof(DataSource))]
        public void Encrypt(Tuple<byte[], byte[], byte[], byte[]> values)
        {
            byte[] enc = Salsa20.Encrypt(values.Item3, values.Item1, values.Item2);
            Assert.AreEqual(values.Item4, enc);
        }

        [TestCaseSource(nameof(DataSource))]
        public void Decrypt(Tuple<byte[], byte[], byte[], byte[]> values)
        {
            byte[] dec = Salsa20.Decrypt(values.Item4, values.Item1, values.Item2);
            Assert.AreEqual(values.Item3, dec);
        }

        [TestCaseSource(nameof(DataSource))]
        public void EncryptStream(Tuple<byte[], byte[], byte[], byte[]> values)
        {
            byte[] enc;
            using (MemoryStream ms = new MemoryStream(values.Item3))
            {
                using (MemoryStream msEnc = new MemoryStream())
                {
                    Salsa20.Encrypt(ms, msEnc, values.Item1, values.Item2);
                    enc = msEnc.ToArray();
                }
            }
            Assert.AreEqual(values.Item4, enc);
        }

        [TestCaseSource(nameof(DataSource))]
        public void DecryptStream(Tuple<byte[], byte[], byte[], byte[]> values)
        {
            byte[] dec;
            using (MemoryStream ms = new MemoryStream(values.Item4))
            {
                using (MemoryStream msDec = new MemoryStream())
                {
                    Salsa20.Decrypt(ms, msDec, values.Item1, values.Item2);
                    dec = msDec.ToArray();
                }
            }
            Assert.AreEqual(values.Item3, dec);
        }

        [Test]
        public void EncryptNullKey()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Salsa20.Encrypt(EmptyArr, null, EmptyArr);
            });
        }

        [Test]
        public void EncryptNullIv()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Salsa20.Encrypt(EmptyArr, EmptyArr, null);
            });
        }

        [Test]
        public void EncryptNullData()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Salsa20.Encrypt(null, EmptyArr, EmptyArr);
            });
        }

        [Test]
        public void DecryptNullKey()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Salsa20.Decrypt(EmptyArr, null, EmptyArr);
            });
        }

        [Test]
        public void DecryptNullIv()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Salsa20.Decrypt(EmptyArr, EmptyArr, null);
            });
        }

        [Test]
        public void DecryptNullData()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Salsa20.Decrypt(null, EmptyArr, EmptyArr);
            });
        }

        [Test]
        public void EncryptStreamNullKey()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Salsa20.Encrypt(new MemoryStream(), new MemoryStream(), null, EmptyArr);
            });
        }

        [Test]
        public void EncryptStreamNullIv()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Salsa20.Encrypt(new MemoryStream(), new MemoryStream(), EmptyArr, null);
            });
        }

        [Test]
        public void EncryptStreamNullInput()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Salsa20.Encrypt(null, new MemoryStream(), EmptyArr, EmptyArr);
            });
        }

        [Test]
        public void EncryptStreamNullOutput()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Salsa20.Encrypt(new MemoryStream(), null, EmptyArr, EmptyArr);
            });
        }

        [Test]
        public void DecryptStreamNullKey()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Salsa20.Decrypt(new MemoryStream(), new MemoryStream(), null, EmptyArr);
            });
        }

        [Test]
        public void DecryptStreamNullIv()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Salsa20.Decrypt(new MemoryStream(), new MemoryStream(), EmptyArr, null);
            });
        }

        [Test]
        public void DecryptStreamNullInput()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Salsa20.Decrypt(null, new MemoryStream(), EmptyArr, EmptyArr);
            });
        }

        [Test]
        public void DecryptStreamNullOutput()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Salsa20.Decrypt(new MemoryStream(), null, EmptyArr, EmptyArr);
            });
        }

        static IEnumerable<Tuple<byte[], byte[], byte[], byte[]>> DataSource()
        {
            using (FileStream fs = StreamHelper.GetFileStreamOpen(@"data\SymKey\salsa20.dat"))
            {
                int total = BinaryHelper.ReadInt32(fs);

                for (int i = 0; i < total; i++)
                {
                    byte[] key = BinaryHelper.ReadLV(fs);
                    byte[] iv = BinaryHelper.ReadLV(fs);
                    byte[] data = BinaryHelper.ReadLV(fs);
                    byte[] enc = BinaryHelper.ReadLV(fs);

                    yield return new Tuple<byte[], byte[], byte[], byte[]>(key, iv, data, enc);
                }
            }
        }
    }
}
