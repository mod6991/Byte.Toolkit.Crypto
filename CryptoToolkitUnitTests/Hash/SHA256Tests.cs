using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Byte.Toolkit.Crypto.Hash;
using Byte.Toolkit.Crypto.IO;
using NUnit.Framework;

namespace CryptoToolkitUnitTests.Hash
{
    public class SHA256Tests
    {
        [TestCaseSource(nameof(BaseTestsSource))]
        public void BaseTests(byte[] data, string hexStr)
        {
            Assert.AreEqual(hexStr, Hex.Encode(SHA256.Hash(data)));
        }

        [TestCaseSource(nameof(AdvancedTestsSource))]
        public void AdvancedTests(Tuple<string, string> results)
        {
            byte[] data = Base64.Decode(results.Item1);
            Assert.AreEqual(results.Item2, Hex.Encode(SHA256.Hash(data)));
        }

        static object[] BaseTestsSource =
        {
            new object[] { new byte[] { }, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
            new object[] { Encoding.ASCII.GetBytes("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
        };

        static IEnumerable<Tuple<string, string>> AdvancedTestsSource()
        {
            using (FileStream fs = new FileStream(@"data/sha256.csv", FileMode.Open, FileAccess.Read))
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
