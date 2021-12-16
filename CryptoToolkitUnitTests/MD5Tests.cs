using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Byte.Toolkit.Crypto.Hash;
using Byte.Toolkit.Crypto.IO;
using NUnit.Framework;

namespace CryptoToolkitUnitTests
{
    public class MD5Tests
    {
        [TestCaseSource(nameof(BaseTestsSource))]
        public void BaseTests(byte[] data, string hexStr)
        {
            Assert.AreEqual(hexStr, Hex.Encode(MD5.Hash(data)));
        }

        [TestCaseSource(nameof(AdvancedTestsSource))]
        public void AdvancedTests(Tuple<string, string> results)
        {
            byte[] data = Base64.Decode(results.Item1);
            Assert.AreEqual(results.Item2, Hex.Encode(MD5.Hash(data)));
        }

        static object[] BaseTestsSource =
        {
            new object[] { new byte[] { }, "d41d8cd98f00b204e9800998ecf8427e" },
            new object[] { Encoding.ASCII.GetBytes("abc"), "900150983cd24fb0d6963f7d28e17f72" },
        };

        static IEnumerable<Tuple<string, string>> AdvancedTestsSource()
        {
            using (FileStream fs = new FileStream(@"data/md5.csv", FileMode.Open, FileAccess.Read))
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
