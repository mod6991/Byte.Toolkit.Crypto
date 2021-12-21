﻿using System;
using System.IO;
using System.Text;

namespace Byte.Toolkit.Crypto.IO
{
    /// <summary>
    /// Binary helper class. Write and read binary values from streams
    /// </summary>
    public static class BinaryHelper
    {
        public const int SIZEOF_BYTE = sizeof(byte);
        public const int SIZEOF_BOOL = sizeof(bool);
        public const int SIZEOF_INT16 = sizeof(Int16);
        public const int SIZEOF_UINT16 = sizeof(UInt16);
        public const int SIZEOF_INT32 = sizeof(Int32);
        public const int SIZEOF_UINT32 = sizeof(UInt32);
        public const int SIZEOF_INT64 = sizeof(Int64);
        public const int SIZEOF_UINT64 = sizeof(UInt64);
        public const int SIZEOF_FLOAT = sizeof(float);
        public const int SIZEOF_DOUBLE = sizeof(double);

        /// <summary>
        /// Write byte to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">Byte value</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void Write(Stream stream, byte value)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            stream.Write(new byte[] { value }, 0, SIZEOF_BYTE);
        }

        /// <summary>
        /// Write bytes to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">Bytes value</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void Write(Stream stream, byte[] value)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            if (value == null)
                throw new ArgumentNullException(nameof(value));

            stream.Write(value, 0, value.Length);
        }

        /// <summary>
        /// Write bool to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">Bool value</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void Write(Stream stream, bool value)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            byte[] data = BitConverter.GetBytes(value);
            stream.Write(data, 0, SIZEOF_BOOL);
        }

        /// <summary>
        /// Write Int16 to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">Int16 value</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void Write(Stream stream, Int16 value)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            byte[] data = BitConverter.GetBytes(value);
            stream.Write(data, 0, SIZEOF_INT16);
        }

        /// <summary>
        /// Write UInt16 to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">UInt16 value</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void Write(Stream stream, UInt16 value)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            byte[] data = BitConverter.GetBytes(value);
            stream.Write(data, 0, SIZEOF_UINT16);
        }

        /// <summary>
        /// Write Int32 to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">Int32 value</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void Write(Stream stream, Int32 value)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            byte[] data = BitConverter.GetBytes(value);
            stream.Write(data, 0, SIZEOF_INT32);
        }

        /// <summary>
        /// Write UInt32 to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">UInt32 value</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void Write(Stream stream, UInt32 value)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            byte[] data = BitConverter.GetBytes(value);
            stream.Write(data, 0, SIZEOF_UINT32);
        }

        /// <summary>
        /// Write Int64 to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">Int64 value</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void Write(Stream stream, Int64 value)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            byte[] data = BitConverter.GetBytes(value);
            stream.Write(data, 0, SIZEOF_INT64);
        }

        /// <summary>
        /// Write UInt64 to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">UInt64 value</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void Write(Stream stream, UInt64 value)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            byte[] data = BitConverter.GetBytes(value);
            stream.Write(data, 0, SIZEOF_UINT64);
        }

        /// <summary>
        /// Write float to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">float value</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void Write(Stream stream, float value)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            byte[] data = BitConverter.GetBytes(value);
            stream.Write(data, 0, SIZEOF_FLOAT);
        }

        /// <summary>
        /// Write double to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">double value</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void Write(Stream stream, double value)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            byte[] data = BitConverter.GetBytes(value);
            stream.Write(data, 0, SIZEOF_DOUBLE);
        }

        /// <summary>
        /// Write string to stream
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">String value</param>
        /// <param name="encoding">String encoding</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void Write(Stream stream, string value, Encoding encoding)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            if (value == null)
                throw new ArgumentNullException(nameof(value));
            if (encoding == null)
                throw new ArgumentNullException(nameof(encoding));

            byte[] data = encoding.GetBytes(value);
            stream.Write(data, 0, data.Length);
        }

        /// <summary>
        /// Write a Length-Value
        /// </summary>
        /// <param name="stream">Output stream</param>
        /// <param name="value">Value</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static void WriteLV(Stream stream, byte[] value)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            if (value == null)
                throw new ArgumentNullException(nameof(value));

            Write(stream, value.Length);
            Write(stream, value);
        }

        /// <summary>
        /// Read byte from stream
        /// </summary>
        /// <param name="stream">Input stream</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte ReadByte(Stream stream)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            byte[] buffer = new byte[SIZEOF_BYTE];

            if (stream.Read(buffer, 0, SIZEOF_BYTE) != SIZEOF_BYTE)
                throw new IOException("Incorrect number of bytes returned");

            return buffer[0];
        }

        /// <summary>
        /// Read bytes from stream
        /// </summary>
        /// <param name="stream">Input stream</param>
        /// <param name="nbBytes">Number of bytes to read</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] ReadBytes(Stream stream, int nbBytes)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            byte[] buffer = new byte[nbBytes];

            if (stream.Read(buffer, 0, nbBytes) != nbBytes)
                throw new IOException("Incorrect number of bytes returned");

            return buffer;
        }

        /// <summary>
        /// Read bool from stream
        /// </summary>
        /// <param name="stream">Input stream</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static bool ReadBool(Stream stream)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            byte[] buffer = new byte[SIZEOF_BOOL];

            if (stream.Read(buffer, 0, SIZEOF_BOOL) != SIZEOF_BOOL)
                throw new IOException("Incorrect number of bytes returned");

            return BitConverter.ToBoolean(buffer, 0);
        }

        /// <summary>
        /// Read Int16 from stream
        /// </summary>
        /// <param name="stream">Input stream</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static Int16 ReadInt16(Stream stream)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            byte[] buffer = new byte[SIZEOF_INT16];

            if (stream.Read(buffer, 0, SIZEOF_INT16) != SIZEOF_INT16)
                throw new IOException("Incorrect number of bytes returned");

            return BitConverter.ToInt16(buffer, 0);
        }

        /// <summary>
        /// Read UInt16 from stream
        /// </summary>
        /// <param name="stream">Input stream</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static UInt16 ReadUInt16(Stream stream)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            byte[] buffer = new byte[SIZEOF_UINT16];

            if (stream.Read(buffer, 0, SIZEOF_UINT16) != SIZEOF_UINT16)
                throw new IOException("Incorrect number of bytes returned");

            return BitConverter.ToUInt16(buffer, 0);
        }

        /// <summary>
        /// Read Int32 from stream
        /// </summary>
        /// <param name="stream">Input stream</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static Int32 ReadInt32(Stream stream)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            byte[] buffer = new byte[SIZEOF_INT32];

            if (stream.Read(buffer, 0, SIZEOF_INT32) != SIZEOF_INT32)
                throw new IOException("Incorrect number of bytes returned");

            return BitConverter.ToInt32(buffer, 0);
        }

        /// <summary>
        /// Read UInt32 from stream
        /// </summary>
        /// <param name="stream">Input stream</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static UInt32 ReadUInt32(Stream stream)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            byte[] buffer = new byte[SIZEOF_UINT32];

            if (stream.Read(buffer, 0, SIZEOF_UINT32) != SIZEOF_UINT32)
                throw new IOException("Incorrect number of bytes returned");

            return BitConverter.ToUInt32(buffer, 0);
        }

        /// <summary>
        /// Read Int64 from stream
        /// </summary>
        /// <param name="stream">Input stream</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static Int64 ReadInt64(Stream stream)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            byte[] buffer = new byte[SIZEOF_INT64];

            if (stream.Read(buffer, 0, SIZEOF_INT64) != SIZEOF_INT64)
                throw new IOException("Incorrect number of bytes returned");

            return BitConverter.ToInt64(buffer, 0);
        }

        /// <summary>
        /// Read UInt64 from stream
        /// </summary>
        /// <param name="stream">Input stream</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static UInt64 ReadUInt64(Stream stream)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            byte[] buffer = new byte[SIZEOF_UINT64];

            if (stream.Read(buffer, 0, SIZEOF_UINT64) != SIZEOF_UINT64)
                throw new IOException("Incorrect number of bytes returned");

            return BitConverter.ToUInt64(buffer, 0);
        }

        /// <summary>
        /// Read float from stream
        /// </summary>
        /// <param name="stream">Input stream</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static float ReadFloat(Stream stream)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            byte[] buffer = new byte[SIZEOF_FLOAT];

            if (stream.Read(buffer, 0, SIZEOF_FLOAT) != SIZEOF_FLOAT)
                throw new IOException("Incorrect number of bytes returned");

            return BitConverter.ToSingle(buffer, 0);
        }

        /// <summary>
        /// Read double from stream
        /// </summary>
        /// <param name="stream">Input stream</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static double ReadDouble(Stream stream)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            byte[] buffer = new byte[SIZEOF_DOUBLE];

            if (stream.Read(buffer, 0, SIZEOF_DOUBLE) != SIZEOF_DOUBLE)
                throw new IOException("Incorrect number of bytes returned");

            return BitConverter.ToDouble(buffer, 0);
        }

        /// <summary>
        /// Read a Length-Value
        /// </summary>
        /// <param name="stream">Input stream</param>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] ReadLV(Stream stream)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            int valueLength = ReadInt32(stream);
            return ReadBytes(stream, valueLength);
        }
    }
}
