using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Byte.Toolkit.Crypto.IO;
using NUnit.Framework;

namespace CryptoToolkitUnitTests.IO
{
    public class HexTests
    {
        [TestCaseSource(nameof(BaseTestsSource))]
        public void BaseTests(byte[] data, string hexStr)
        {
            Assert.AreEqual(hexStr, Hex.Encode(data));
        }

        [TestCaseSource(nameof(AdvancedTestsSource))]
        public void AdvancedTests(Tuple<string, string> results)
        {
            byte[] data = Base64.Decode(results.Item2);
            Assert.AreEqual(results.Item1, Hex.Encode(data));
        }

        static object[] BaseTestsSource =
        {
            new object[] { new byte[] { }, "" },
            new object[] { new byte[] { 0x12 }, "12" },
            new object[] { new byte[] { 0x12, 0x34 }, "1234" },
            new object[] { new byte[] { 0x12, 0x34, 0x56 }, "123456" },
            new object[] { new byte[] { 0x12, 0x34, 0x56, 0xdf }, "123456df" }
        };

        static IEnumerable<Tuple<string, string>> AdvancedTestsSource()
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
