using Org.BouncyCastle.Crypto.Digests;

namespace Byte.Toolkit.Crypto.Hash
{
    public static class SHA256
    {
        /// <summary>
        /// Hash data with SHA256
        /// </summary>
        /// <param name="data">Data to hash</param>
        /// <returns>Hash</returns>
        public static byte[] Hash(byte[] data)
        {
            byte[] result = new byte[32];

            Sha256Digest sha256 = new Sha256Digest();
            sha256.BlockUpdate(data, 0, data.Length);
            sha256.DoFinal(result, 0);

            return result;
        }

        /// <summary>
        /// Hash stream with SHA256
        /// </summary>
        /// <param name="input">Input stream</param>
        /// <param name="bufferSize">Buffer size</param>
        /// <returns>Hash</returns>
        public static byte[] Hash(Stream input, int bufferSize = 4096)
        {
            byte[] result = new byte[32];

            Sha256Digest sha256 = new Sha256Digest();
            int bytesRead;
            byte[] buffer = new byte[bufferSize];

            do
            {
                bytesRead = input.Read(buffer, 0, bufferSize);
                if (bytesRead > 0)
                    sha256.BlockUpdate(buffer, 0, bytesRead);
            } while (bytesRead == bufferSize);


            sha256.DoFinal(result, 0);

            return result;
        }

        /// <summary>
        /// Hash file with SHA256
        /// </summary>
        /// <param name="filePath">File path</param>
        /// <param name="bufferSize">Buffer size</param>
        /// <returns>Hash</returns>
        public static byte[] Hash(string filePath, int bufferSize = 4096)
        {
            using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                return Hash(fs, bufferSize);
            }
        }
    }
}
