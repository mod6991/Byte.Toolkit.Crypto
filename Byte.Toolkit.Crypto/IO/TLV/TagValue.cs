using System;

namespace Byte.Toolkit.Crypto.IO.TLV
{
    public sealed class TlvException : Exception
    {
        public TlvException(string message) : base(message) { }
    }

    /// <summary>
    /// Tag-Value container
    /// </summary>
    public sealed class TagValue
    {
        public TagValue(string tag, byte[] value)
        {
            Tag = tag ?? throw new ArgumentNullException(nameof(tag));
            Value = value ?? throw new ArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Tag
        /// </summary>
        public string Tag { get; }
        /// <summary>
        /// Value
        /// </summary>
        public byte[] Value { get; }
    }
}
