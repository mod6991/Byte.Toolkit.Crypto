using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Byte.Toolkit.Crypto.IO;
using Byte.Toolkit.Crypto.PubKey;
using NUnit.Framework;

namespace CryptoToolkitUnitTests.SymKey
{
    public class RSATests
    {
        [Test]
        public void LoadPublicPem()
        {
            Assert.Multiple(() =>
            {
                Assert.DoesNotThrow(() => RSA.LoadFromPEM(@"data\pub_key1.pem"));
                Assert.DoesNotThrow(() => RSA.LoadFromPEM(@"data\pub_key2.pem"));
            });
        }

        [Test]
        public void LoadPrivatePemWithPassword()
        {
            Assert.DoesNotThrow(() => RSA.LoadFromPEM(@"data\pk_key1.pem", "test1234"));
        }

        [Test]
        public void LoadPrivatePemWithoutPassword()
        {
            Assert.DoesNotThrow(() => RSA.LoadFromPEM(@"data\pk_key2.pem"));
        }

        [TestCaseSource(nameof(CsvTestSource1))]
        public void Decrypt(Tuple<string, string> values)
        {
            var rsa = RSA.LoadFromPEM(@"data\pk_key1.pem", "test1234");

            byte[] data = Base64.Decode(values.Item1);
            byte[] enc = Base64.Decode(values.Item2);

            byte[] calculatedDec = RSA.Decrypt(rsa, enc);
            Assert.AreEqual(data, calculatedDec);
        }

        static IEnumerable<Tuple<string, string>> CsvTestSource1()
        {
            using (FileStream fs = new FileStream(@"data\rsa1.csv", FileMode.Open, FileAccess.Read))
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
