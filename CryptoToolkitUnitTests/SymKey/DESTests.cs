using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Byte.Toolkit.Crypto.IO;
using Byte.Toolkit.Crypto.SymKey;
using NUnit.Framework;

namespace CryptoToolkitUnitTests.SymKey
{
    public class DESTests
    {
        [TestCaseSource(nameof(CsvTestSource))]
        public void Encrypt(Tuple<string, string, string, string> values)
        {
            byte[] key = Base64.Decode(values.Item1);
            byte[] iv = Base64.Decode(values.Item2);
            byte[] data = Base64.Decode(values.Item3);
            byte[] enc = Base64.Decode(values.Item4);

            byte[] calculatedEnc = DES.EncryptCBC(data, key, iv);
            Assert.AreEqual(enc, calculatedEnc);
        }

        [TestCaseSource(nameof(CsvTestSource))]
        public void Decrypt(Tuple<string, string, string, string> values)
        {
            byte[] key = Base64.Decode(values.Item1);
            byte[] iv = Base64.Decode(values.Item2);
            byte[] data = Base64.Decode(values.Item3);
            byte[] enc = Base64.Decode(values.Item4);

            byte[] calculatedDec = DES.DecryptCBC(enc, key, iv);
            Assert.AreEqual(data, calculatedDec);
        }

        static IEnumerable<Tuple<string, string, string, string>> CsvTestSource()
        {
            using (FileStream fs = new FileStream(@"data/des.csv", FileMode.Open, FileAccess.Read))
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
                            yield return new Tuple<string, string, string, string>(sp[0], sp[1], sp[2], sp[3]);
                        }
                    }
                }
            }
        }
    }
}
