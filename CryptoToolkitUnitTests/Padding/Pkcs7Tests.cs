using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Byte.Toolkit.Crypto.Hash;
using Byte.Toolkit.Crypto.IO;
using Byte.Toolkit.Crypto.Padding;
using NUnit.Framework;

namespace CryptoToolkitUnitTests.Padding
{
    public class Pkcs7Tests
    {
        [TestCaseSource(nameof(DataSource))]
        public void Pad(Tuple<byte[], byte[]> values)
        {
            byte[] padded = new Pkcs7Padding().Pad(values.Item1, 16);
            Assert.AreEqual(values.Item2, padded);
        }

        [TestCaseSource(nameof(DataSource))]
        public void Unpad(Tuple<byte[], byte[]> values)
        {
            byte[] unpadded = new Pkcs7Padding().Unpad(values.Item2, 16);
            Assert.AreEqual(values.Item1, unpadded);
        }

        [Test]
        public void PadBadBlockSize()
        {
            Assert.Throws<ArgumentException>(() =>
            {
                new Pkcs7Padding().Pad(new byte[] { }, 0);
            });
        }

        [Test]
        public void PadNull()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                new Pkcs7Padding().Pad(null, 16);
            });
        }

        [Test]
        public void UnpadBadBlockSize()
        {
            Assert.Throws<ArgumentException>(() =>
            {
                new Pkcs7Padding().Unpad(new byte[] { }, 0);
            });
        }

        [Test]
        public void UnPadBadPaddingLength()
        {
            Assert.Throws<PaddingException>(() =>
            {
                new Pkcs7Padding().Unpad(Hex.Decode("000f0f0f0f0f0f0f0f0f0f0f0f0f0f"), 16);
            });
        }

        [Test]
        public void UnPadBadPaddingData()
        {
            Assert.Throws<PaddingException>(() =>
            {
                new Pkcs7Padding().Unpad(Hex.Decode("000f0f0f0f0f0f0f0a0f0f0f0f0f0f0f"), 16);
            });
        }

        [Test]
        public void UnPadNull()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                new Pkcs7Padding().Unpad(null, 16);
            });
        }

        static IEnumerable<Tuple<byte[], byte[]>> DataSource()
        {
            using (FileStream fsDat = StreamHelper.GetFileStreamOpen(@"data\Padding\pkcs7_data.dat"))
            {
                using (FileStream fsPadded = StreamHelper.GetFileStreamOpen(@"data\Padding\pkcs7_padded.dat"))
                {
                    int total = BinaryHelper.ReadInt32(fsDat);
                    BinaryHelper.ReadInt32(fsPadded);

                    for (int i = 0; i < total; i++)
                    {
                        byte[] data = BinaryHelper.ReadLV(fsDat);
                        byte[] padded = BinaryHelper.ReadLV(fsPadded);

                        yield return new Tuple<byte[], byte[]>(data, padded);
                    }
                }
            }
        }
    }
}
