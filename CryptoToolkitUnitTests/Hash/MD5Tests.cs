using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Byte.Toolkit.Crypto.Hash;
using Byte.Toolkit.Crypto.IO;
using NUnit.Framework;

namespace CryptoToolkitUnitTests.Hash
{
    public class MD5Tests
    {
        [TestCaseSource(nameof(CsvTestSource))]
        public void Hash(Tuple<string, string> values)
        {
            byte[] data = Base64.Decode(values.Item1);
            Assert.AreEqual(values.Item2, Hex.Encode(MD5.Hash(data)));
        }

        static IEnumerable<Tuple<string, string>> CsvTestSource()
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
