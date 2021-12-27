using System;
using System.Collections.Generic;
using System.IO;
using Byte.Toolkit.Crypto.IO;
using Byte.Toolkit.Crypto.Padding;
using NUnit.Framework;

namespace CryptoToolkitUnitTests.Padding
{
    public class AnsiX923Tests
    {
        [TestCaseSource(nameof(DataSource))]
        public void Pad(Tuple<byte[], byte[]> values)
        {
            byte[] padded = new AnsiX923Padding().Pad(values.Item1, 16);
            Assert.AreEqual(values.Item2, padded);
        }

        [TestCaseSource(nameof(DataSource))]
        public void Unpad(Tuple<byte[], byte[]> values)
        {
            byte[] unpadded = new AnsiX923Padding().Unpad(values.Item2, 16);
            Assert.AreEqual(values.Item1, unpadded);
        }

        [Test]
        public void PadBadBlockSize()
        {
            Assert.Throws<ArgumentException>(() =>
            {
                new AnsiX923Padding().Pad(new byte[] { }, 0);
            });
        }

        [Test]
        public void PadNull()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                new AnsiX923Padding().Pad(null, 16);
            });
        }

        [Test]
        public void UnpadBadBlockSize()
        {
            Assert.Throws<ArgumentException>(() =>
            {
                new AnsiX923Padding().Unpad(new byte[] { }, 0);
            });
        }

        [Test]
        public void UnPadBadPaddingLength()
        {
            Assert.Throws<PaddingException>(() =>
            {
                new AnsiX923Padding().Unpad(Hex.Decode("000000000000000000000000000000"), 16);
            });
        }

        [Test]
        public void UnPadNull()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                new AnsiX923Padding().Unpad(null, 16);
            });
        }

        static IEnumerable<Tuple<byte[], byte[]>> DataSource()
        {
            using (FileStream fsDat = StreamHelper.GetFileStreamOpen(@"data\Padding\ansix923_data.dat"))
            {
                using (FileStream fsPadded = StreamHelper.GetFileStreamOpen(@"data\Padding\ansix923_padded.dat"))
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
