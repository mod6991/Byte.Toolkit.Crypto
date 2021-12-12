//using System;
//using System.Collections.Generic;
//using System.Linq;
//using System.Text;
//using System.Threading.Tasks;

//namespace Byte.Toolkit.Crypto.IO.TLV
//{
//    //TODO
//    public sealed class StringTlvWriter
//    {
//        private Stream _output;
//        private byte _tagLength;
//        private List<string> _tags;
//        private Encoding _encoding;
//        private StreamWriter _sw;

//        public StringTlvWriter(Stream output, byte tagLength, Encoding encoding)
//        {
//            _output = output;
//            _tagLength = tagLength;
//            _tags = new List<string>();
//            _encoding = encoding;
//            _sw = new StreamWriter(output, _encoding);

//            _sw.Write($"{_tagLength:000}");
//            //string encodingHexStr = Hex.Encode(BitConverter.GetBytes(_encoding.CodePage));
//            //_sw.Write(encodingHexStr);
//        }

//        public void Write(string tag, string value)
//        {
//            if (string.IsNullOrWhiteSpace(tag))
//                throw new ArgumentException(nameof(tag));

//            if (string.IsNullOrEmpty(value))
//                throw new ArgumentException(nameof(value));

//            if (_tags.Contains(tag))
//                throw new TlvException($"Tag '{tag}' already written");
//            else
//                _tags.Add(tag);

//            string padTag = tag.PadRight(_tagLength);

//            if (padTag.Length != _tagLength)
//                throw new TlvException("Invalid tag length");

//            _sw.Write(padTag);
//            //_sw.Write()
//        }
//    }
//}
