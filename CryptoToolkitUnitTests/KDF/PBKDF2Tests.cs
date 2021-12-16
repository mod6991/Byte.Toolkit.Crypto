using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Byte.Toolkit.Crypto.KDF;
using Byte.Toolkit.Crypto.IO;
using NUnit.Framework;

namespace CryptoToolkitUnitTests.KDF
{
    public class PBKDF2Tests
    {
        [TestCaseSource(nameof(CsvTestSource))]
        public void GenerateKeyFromPassword(Tuple<string, string, string> values)
        {
            string password = values.Item1;
            byte[] salt = Hex.Decode(values.Item2);
            string hexKey = values.Item3;

            byte[] key = PBKDF2.GenerateKeyFromPassword(32, password, salt, 50000);

            Assert.AreEqual(hexKey, Hex.Encode(key));
        }

        static IEnumerable<Tuple<string, string, string>> CsvTestSource()
        {
            using (FileStream fs = new FileStream(@"data/pbkdf2.csv", FileMode.Open, FileAccess.Read))
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
                            yield return new Tuple<string, string, string>(sp[0], sp[1], sp[2]);
                        }
                    }
                }
            }
        }
    }
}
