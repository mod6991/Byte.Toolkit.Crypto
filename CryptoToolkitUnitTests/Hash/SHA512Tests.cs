﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Byte.Toolkit.Crypto.Hash;
using Byte.Toolkit.Crypto.IO;
using NUnit.Framework;

namespace CryptoToolkitUnitTests.Hash
{
    public class SHA512Tests
    {
        [TestCaseSource(nameof(DataSource))]
        public void Hash(Tuple<byte[], string> values)
        {
            byte[] hash = SHA512.Hash(values.Item1);
            Assert.AreEqual(values.Item2, Hex.Encode(hash));
        }

        [Test]
        public void HashFile()
        {
            string hashStr = File.ReadAllText(@"data\Hash\sha512.dat.txt", Encoding.ASCII);
            byte[] hash = SHA512.Hash(@"data\Hash\sha512.dat");
            Assert.AreEqual(hashStr, Hex.Encode(hash));
        }

        [Test]
        public void HashStream()
        {
            string hashStr = File.ReadAllText(@"data\Hash\sha512.dat.txt", Encoding.ASCII);
            byte[] hash;
            using (FileStream fs = StreamHelper.GetFileStreamOpen(@"data\Hash\sha512.dat"))
            {
                hash = SHA512.Hash(fs);
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
            using (FileStream fsDat = StreamHelper.GetFileStreamOpen(@"data\Hash\sha512.dat"))
            {
                using (FileStream fsTxt = StreamHelper.GetFileStreamOpen(@"data\Hash\sha512.txt"))
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
