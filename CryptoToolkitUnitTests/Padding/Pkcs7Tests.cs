using Byte.Toolkit.Crypto.Hash;
using Byte.Toolkit.Crypto.IO;
using Byte.Toolkit.Crypto.Padding;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace CryptoToolkitUnitTests.Padding
{
    public class Pkcs7Tests
    {
        [TestCaseSource(nameof(AdvancedTestsSource))]
        public void PadTests(Tuple<string, string> results)
        {
            byte[] data = Base64.Decode(results.Item1);
            byte[] padded = new Pkcs7Padding().Pad(data, 16);
            Assert.AreEqual(results.Item2, Base64.Encode(padded));
        }

        [TestCaseSource(nameof(AdvancedTestsSource))]
        public void UnpadTests(Tuple<string, string> results)
        {
            byte[] padded = Base64.Decode(results.Item2);
            byte[] data = new Pkcs7Padding().UnPad(padded, 16);
            Assert.AreEqual(results.Item1, Base64.Encode(data));
        }

        static IEnumerable<Tuple<string, string>> AdvancedTestsSource()
        {
            using (FileStream fs = new FileStream(@"data/pkcs7.csv", FileMode.Open, FileAccess.Read))
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
