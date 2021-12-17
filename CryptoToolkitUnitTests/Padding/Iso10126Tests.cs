using Byte.Toolkit.Crypto.IO;
using Byte.Toolkit.Crypto.Padding;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace CryptoToolkitUnitTests.Padding
{
    public class Iso10126Tests
    {
        [Test]
        public void PadEmpty()
        {
            const int blockSize = 16;

            byte[] padded = new Iso10126Padding().Pad(new byte[] { }, blockSize);
            Assert.Multiple(() =>
            {
                Assert.AreEqual(blockSize, padded.Length);
                Assert.AreEqual(blockSize, (int)padded[padded.Length - 1]);
            });
        }

        [TestCaseSource(nameof(CsvTestSource))]
        public void Pad(Tuple<string, string> values)
        {
            byte[] data = Base64.Decode(values.Item1);
            byte[] padded = Base64.Decode(values.Item2);
            byte[] calculatedPadded = new Iso10126Padding().Pad(data, 16);

            byte padLength = padded[padded.Length - 1];

            Assert.Multiple(() =>
            {
                Assert.AreEqual(padded.Length, calculatedPadded.Length);
                string hexData = Hex.Encode(data);
                string hexCalculatedPadded = Hex.Encode(calculatedPadded);
                Assert.AreEqual(hexData, hexCalculatedPadded.Substring(0, data.Length * 2));
                Assert.AreEqual(padded[padded.Length - 1], calculatedPadded[calculatedPadded.Length - 1]);
            });
        }

        [Test]
        public void UnpadEmpty()
        {
            byte[] data = new Iso10126Padding().UnPad(Hex.Decode("00000000000000000000000000000010"), 16);
            Assert.AreEqual(new byte[] { }, data);
        }

        [TestCaseSource(nameof(CsvTestSource))]
        public void Unpad(Tuple<string, string> values)
        {
            byte[] padded = Base64.Decode(values.Item2);
            byte[] data = new Iso10126Padding().UnPad(padded, 16);
            Assert.AreEqual(values.Item1, Base64.Encode(data));
        }

        static IEnumerable<Tuple<string, string>> CsvTestSource()
        {
            using (FileStream fs = new FileStream(@"data/iso10126.csv", FileMode.Open, FileAccess.Read))
            {
                using (StreamReader sr = new StreamReader(fs, Encoding.UTF8))
                {
                    sr.ReadLine(); // header

                    while (!sr.EndOfStream)
                    {
                        string line = sr.ReadLine();
                        if (!string.IsNullOrWhiteSpace(line))
                        {
                            string[] sp = line.Split(',');
                            yield return new Tuple<string, string>(sp[0], sp[1]);
                        }
                    }
                }
            }
        }
    }
}
