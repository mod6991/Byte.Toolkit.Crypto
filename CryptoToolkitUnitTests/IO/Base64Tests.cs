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
        [TestCaseSource(nameof(BaseTestsSource))]
        public void BaseTests(byte[] data, string b64Str)
        {
            Assert.AreEqual(b64Str, Base64.Encode(data));
        }

        [TestCaseSource(nameof(AdvancedTestsSource))]
        public void AdvancedTests(Tuple<string, string> results)
        {
            byte[] data = Hex.Decode(results.Item1);
            Assert.AreEqual(results.Item2, Base64.Encode(data));
        }

        static object[] BaseTestsSource =
        {
            new object[] { new byte[] { }, "" },
            new object[] { new byte[] { 0x12 }, "Eg==" },
            new object[] { new byte[] { 0x12, 0x34 }, "EjQ=" },
            new object[] { new byte[] { 0x12, 0x34, 0x56 }, "EjRW" },
            new object[] { new byte[] { 0x12, 0x34, 0x56, 0x78 }, "EjRWeA==" }
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