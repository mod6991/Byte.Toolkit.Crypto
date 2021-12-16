using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Byte.Toolkit.Crypto.Hash;
using Byte.Toolkit.Crypto.IO;
using NUnit.Framework;

namespace CryptoToolkitUnitTests.Hash
{
    public class SHA1Tests
    {
        [TestCaseSource(nameof(BaseTestsSource))]
        public void BaseTests(byte[] data, string hexStr)
        {
            Assert.AreEqual(hexStr, Hex.Encode(SHA1.Hash(data)));
        }

        [TestCaseSource(nameof(AdvancedTestsSource))]
        public void AdvancedTests(Tuple<string, string> results)
        {
            byte[] data = Base64.Decode(results.Item1);
            Assert.AreEqual(results.Item2, Hex.Encode(SHA1.Hash(data)));
        }

        static object[] BaseTestsSource =
        {
            new object[] { new byte[] { }, "da39a3ee5e6b4b0d3255bfef95601890afd80709" },
            new object[] { Encoding.ASCII.GetBytes("abc"), "a9993e364706816aba3e25717850c26c9cd0d89d" },
        };

        static IEnumerable<Tuple<string, string>> AdvancedTestsSource()
        {
            using (FileStream fs = new FileStream(@"data/sha1.csv", FileMode.Open, FileAccess.Read))
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
