using Byte.Toolkit.Crypto.IO;
using Byte.Toolkit.Crypto.Padding;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace CryptoToolkitUnitTests.Padding
{
    public class AnsiX923Tests
    {
        [Test]
        public void PadEmpty()
        {
            byte[] padded = new AnsiX923Padding().Pad(new byte[] { }, 16);
            Assert.AreEqual("00000000000000000000000000000010", Hex.Encode(padded));
        }

        [TestCaseSource(nameof(CsvTestSource))]
        public void Pad(Tuple<string, string> values)
        {
            byte[] data = Base64.Decode(values.Item1);
            byte[] padded = new AnsiX923Padding().Pad(data, 16);
            Assert.AreEqual(values.Item2, Base64.Encode(padded));
        }

        [Test]
        public void UnpadEmpty()
        {
            byte[] data = new AnsiX923Padding().UnPad(Hex.Decode("00000000000000000000000000000010"), 16);
            Assert.AreEqual(new byte[] { }, data);
        }

        [TestCaseSource(nameof(CsvTestSource))]
        public void Unpad(Tuple<string, string> values)
        {
            byte[] padded = Base64.Decode(values.Item2);
            byte[] data = new AnsiX923Padding().UnPad(padded, 16);
            Assert.AreEqual(values.Item1, Base64.Encode(data));
        }

        static IEnumerable<Tuple<string, string>> CsvTestSource()
        {
            using (FileStream fs = new FileStream(@"data/ansix923.csv", FileMode.Open, FileAccess.Read))
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
