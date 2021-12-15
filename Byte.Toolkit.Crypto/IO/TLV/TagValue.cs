using System;

namespace Byte.Toolkit.Crypto.IO.TLV
{
    public sealed class TlvException : Exception
    {
        public TlvException(string message) : base(message) { }
    }

    public sealed class TagValue
    {
        public TagValue(string tag, byte[] value)
        {
            Tag = tag;
            Value = value;
        }

        public string Tag { get; }
        public byte[] Value { get; }
    }
}
