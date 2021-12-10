using System.Text;

#pragma warning disable CS8603

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

    public sealed class BinaryTlvWriter
    {
        private Stream _output;
        private byte _tagLength;
        private List<string> _tags;

        public BinaryTlvWriter(Stream output, byte tagLength)
        {
            _output = output;
            _tagLength = tagLength;
            _tags = new List<string>();

            BinaryHelper.WriteByte(_output, _tagLength);
        }

        /// <summary>
        /// Write TLV into output stream
        /// </summary>
        /// <param name="tag">Tag</param>
        /// <param name="value">Value</param>
        public void Write(string tag, byte[] value)
        {
            if (string.IsNullOrWhiteSpace(tag))
                throw new ArgumentException("tag");

            if (value == null)
                throw new ArgumentNullException("value");

            if (_tags.Contains(tag))
                throw new TlvException($"Tag '{tag}' already written");
            else
                _tags.Add(tag);

            string padTag = tag.PadRight(_tagLength);

            if (padTag.Length != _tagLength)
                throw new TlvException("Invalid tag length");

            BinaryHelper.WriteString(_output, padTag, Encoding.ASCII);
            BinaryHelper.WriteLV(_output, value);
        }

        /// <summary>
        /// Build a TLV list
        /// </summary>
        /// <param name="values">Values to write</param>
        /// <param name="tagLength">Tag length for the values</param>
        public static byte[] BuildTlvList(Dictionary<string, byte[]> values, byte tagLength)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                BinaryTlvWriter tlv = new BinaryTlvWriter(ms, tagLength);
                foreach (KeyValuePair<string, byte[]> kvp in values)
                    tlv.Write(kvp.Key, kvp.Value);

                return ms.ToArray();
            }
        }
    }

    public class BinaryTlvReader
    {
        private Stream _input;
        private byte _tagLength;

        public BinaryTlvReader(Stream input)
        {
            _input = input;
            _tagLength = BinaryHelper.ReadByte(_input);
        }

        /// <summary>
        /// Read a single TLV from the input stream
        /// </summary>
        public TagValue Read()
        {
            byte[] tagData = new byte[_tagLength];
            if (_input.Read(tagData, 0, _tagLength) == 0)
                return null;

            string tag = Encoding.ASCII.GetString(tagData).Trim();
            byte[] value = BinaryHelper.ReadLV(_input);
            return new TagValue(tag, value);
        }

        /// <summary>
        /// Read all TLV from the input stream
        /// </summary>
        public Dictionary<string, byte[]> ReadAll()
        {
            using (MemoryStream ms = new MemoryStream())
            {
                _input.Seek(0, SeekOrigin.Begin);
                StreamHelper.WriteStream(_input, ms);
                return TlvListFromBytes(ms.ToArray());
            }
        }

        /// <summary>
        /// Read a TLV list from bytes
        /// </summary>
        /// <param name="data">Data containing the TLV list</param>
        public static Dictionary<string, byte[]> TlvListFromBytes(byte[] data)
        {
            Dictionary<string, byte[]> tlvList = new Dictionary<string, byte[]>();

            using (MemoryStream ms = new MemoryStream(data))
            {
                BinaryTlvReader tlv = new BinaryTlvReader(ms);
                TagValue tv;

                do
                {
                    tv = tlv.Read();
                    if (tv != null)
                        tlvList.Add(tv.Tag, tv.Value);
                } while (tv != null);
            }

            return tlvList;
        }
    }
}
