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
        //+ hash file
        //+ hash stream

        [TestCaseSource(nameof(DataSource))]
        public void Hash(Tuple<byte[], string> values)
        {
            byte[] hash = MD5.Hash(values.Item1);
            Assert.AreEqual(values.Item2, Hex.Encode(hash));
        }

        [Test]
        public void HashFile()
        {
            string hashStr = File.ReadAllText(@"data\Hash\md5.dat.txt", Encoding.ASCII);
            byte[] hash = MD5.Hash(@"data\Hash\md5.dat");
            Assert.AreEqual(hashStr, Hex.Encode(hash));
        }

        [Test]
        public void HashStream()
        {
            string hashStr = File.ReadAllText(@"data\Hash\md5.dat.txt", Encoding.ASCII);
            byte[] hash;
            using(FileStream fs = StreamHelper.GetFileStreamOpen(@"data\Hash\md5.dat"))
            {
                hash = MD5.Hash(fs);
            }
            Assert.AreEqual(hashStr, Hex.Encode(hash));
        }

        [Test]
        public void HashNull()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                Hex.Encode(null);
            });
        }

        static IEnumerable<Tuple<byte[], string>> DataSource()
        {
            using (FileStream fsDat = StreamHelper.GetFileStreamOpen(@"data\Hash\md5.dat"))
            {
                using (FileStream fsTxt = StreamHelper.GetFileStreamOpen(@"data\Hash\md5.txt"))
                {
                    using (StreamReader sr = new StreamReader(fsTxt, Encoding.ASCII))
                    {
                        int total = BinaryHelper.ReadInt32(fsDat);

                        for (int i = 0; i < total; i++)
                        {
                            string line = sr.ReadLine();
                            byte[] data = BinaryHelper.ReadLV(fsDat);

                            yield return new Tuple<byte[], string>(data, line);
                        }
                    }
                }

            }
        }
    }
}
