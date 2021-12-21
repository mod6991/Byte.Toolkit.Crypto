using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Byte.Toolkit.Crypto.IO.TLV
{
    /// <summary>
    /// Binary writer for Tag-Length-Value
    /// </summary>
    public sealed class BinaryTlvWriter
    {
        private Stream _output;
        private byte _tagLength;
        private List<string> _tags;

        public BinaryTlvWriter(Stream output, byte tagLength)
        {
            _output = output ?? throw new ArgumentNullException(nameof(output));
            _tagLength = tagLength;
            _tags = new List<string>();

            BinaryHelper.Write(_output, _tagLength);
        }

        /// <summary>
        /// Write a TLV into the stream
        /// </summary>
        /// <param name="tag">Tag</param>
        /// <param name="value">Value</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="TlvException"></exception>
        public void Write(string tag, byte[] value)
        {
            if (tag == null)
                throw new ArgumentNullException(nameof(tag));
            if (value == null)
                throw new ArgumentNullException(nameof(value));

            if (_tags.Contains(tag))
                throw new TlvException($"Tag '{tag}' already written");
            else
                _tags.Add(tag);

            string padTag = tag.PadRight(_tagLength);

            if (padTag.Length != _tagLength)
                throw new TlvException("Invalid tag length");

            BinaryHelper.Write(_output, padTag, Encoding.ASCII);
            BinaryHelper.WriteLV(_output, value);
        }

        /// <summary>
        /// Build a TLV list
        /// </summary>
        /// <param name="values">Values</param>
        /// <param name="tagLength">Tag length</param>
        /// <returns>TLV list data</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] BuildTlvList(Dictionary<string, byte[]> values, byte tagLength)
        {
            if (values == null)
                throw new ArgumentNullException(nameof(values));

            using (MemoryStream ms = new MemoryStream())
            {
                BinaryTlvWriter tlv = new BinaryTlvWriter(ms, tagLength);
                foreach (KeyValuePair<string, byte[]> kvp in values)
                    tlv.Write(kvp.Key, kvp.Value);

                return ms.ToArray();
            }
        }
    }

    /// <summary>
    /// Binary reader for Tag-Length-Value
    /// </summary>
    public sealed class BinaryTlvReader
    {
        private Stream _input;
        private byte _tagLength;

        public BinaryTlvReader(Stream input)
        {
            _input = input ?? throw new ArgumentNullException(nameof(input));
            _tagLength = BinaryHelper.ReadByte(_input);
        }

        /// <summary>
        /// Read a TLV from the stream
        /// </summary>
        /// <returns>Tag and value</returns>
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
        /// Read all TLV
        /// </summary>
        /// <returns>TLV dictionary</returns>
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
        /// Read all TLV from data
        /// </summary>
        /// <param name="data">Data to read</param>
        /// <returns>TLV dictionary</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static Dictionary<string, byte[]> TlvListFromBytes(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

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
