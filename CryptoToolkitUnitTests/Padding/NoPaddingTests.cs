﻿using System;
using Byte.Toolkit.Crypto.IO;
using Byte.Toolkit.Crypto.Padding;
using NUnit.Framework;

namespace CryptoToolkitUnitTests.Padding
{
    public class NoPaddingTests
    {
        [Test]
        [TestCase("fe")]
        public void Pad(string dataStr)
        {
            byte[] data = Hex.Decode(dataStr);
            byte[] padded = new NoPadding().Pad(data, 16);
            Assert.That(data == padded);
        }

        [Test]
        [TestCase("fe00000000000000000000000000000f")]
        public void Unpad(string paddedStr)
        {
            byte[] padded = Hex.Decode(paddedStr);

            byte[] calcData = new NoPadding().Unpad(padded, 16);
            Assert.AreEqual(padded, calcData);
        }

        [Test]
        public void PadBadBlockSize()
        {
            Assert.Throws<ArgumentException>(() =>
            {
                new NoPadding().Pad(new byte[] { }, 0);
            });
        }

        [Test]
        public void PadNull()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                new NoPadding().Pad(null, 16);
            });
        }

        [Test]
        public void UnpadBadBlockSize()
        {
            Assert.Throws<ArgumentException>(() =>
            {
                new NoPadding().Unpad(new byte[] { }, 0);
            });
        }

        [Test]
        public void UnPadNull()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                new NoPadding().Unpad(null, 16);
            });
        }
    }
}
