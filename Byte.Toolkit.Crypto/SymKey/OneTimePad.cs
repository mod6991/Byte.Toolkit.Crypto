using System;
using System.IO;

namespace Byte.Toolkit.Crypto.SymKey
{
    public sealed class OneTimePadException : Exception
    {
        public OneTimePadException(string message) : base(message) { }
    }

    public static class OneTimePad
    {
        public static byte[] Process(byte[] data, byte[] pad)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            if (pad == null)
                throw new ArgumentNullException(nameof(pad));

            if (data.Length != pad.Length)
                throw new OneTimePadException($"Data and pad size mismatch");

            byte[] result = new byte[data.Length];

            for (int i = 0; i < data.Length; i++)
                result[i] = (byte)(data[i] ^ pad[i]);

            return result;
        }

        public static void ProcessStreams(Stream dataInput, Stream padInput, Stream output, int bufferSize = 4096)
        {
            int dataBytesRead;
            int padBytesRead;
            byte[] dataBuffer = new byte[bufferSize];
            byte[] padBuffer = new byte[bufferSize];

            do
            {
                dataBytesRead = dataInput.Read(dataBuffer, 0, bufferSize);
                padBytesRead = padInput.Read(padBuffer, 0, bufferSize);

                if (dataBytesRead != padBytesRead)
                    throw new OneTimePadException($"Data and pad size mismatch");

                byte[] result = new byte[dataBytesRead];

                for (int i = 0; i < dataBytesRead; i++)
                    result[i] = (byte)(dataBuffer[i] ^ padBuffer[i]);

                output.Write(result, 0, dataBytesRead);

            } while (dataBytesRead == bufferSize);
        }
    }
}
