using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Byte.Toolkit.Crypto.IO;
using NUnit.Framework;

namespace CryptoToolkitUnitTests.IO
{
    public class Base64Tests
    {
        [Test]
        public void EncodeEmpty()
        {
            Assert.AreEqual("", Base64.Encode(new byte[] { }));
        }

        [TestCaseSource(nameof(CsvTestSource))]
        public void Encode(Tuple<string, string> values)
        {
            byte[] data = Hex.Decode(values.Item1);
            Assert.AreEqual(values.Item2, Base64.Encode(data));
        }

        [Test]
        public void DecodeEmpty()
        {
            Assert.AreEqual(new byte[] { }, Base64.Decode(""));
        }

        [TestCaseSource(nameof(CsvTestSource))]
        public void Decode(Tuple<string, string> values)
        {
            byte[] data = Base64.Decode(values.Item2);
            Assert.AreEqual(values.Item1, Hex.Encode(data));
        }

        static IEnumerable<Tuple<string, string>> CsvTestSource()
        {
            using (FileStream fs = new FileStream(@"data/hex_base64.csv", FileMode.Open, FileAccess.Read))
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