using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
