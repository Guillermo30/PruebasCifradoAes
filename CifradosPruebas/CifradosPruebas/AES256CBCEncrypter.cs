using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AES256
{
    public class AES256CBCEncrypter
    {
        public string Encrypt(string plainText, string key, string iv)
        {
            Aes encryptor = Aes.Create();
            encryptor.Mode = CipherMode.CBC;
            encryptor.KeySize = 256;

            encryptor.Key = getKey(key);
            encryptor.IV = getIV(iv);

            using (MemoryStream memoryStream = new MemoryStream())
            using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
            {
                byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                cryptoStream.FlushFinalBlock();
                byte[] cipherBytes = memoryStream.ToArray();
                string cipherText = Convert.ToBase64String(cipherBytes, 0, cipherBytes.Length);
                return cipherText;
            }
        }

        private byte[] getKey(string key)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            if (keyBytes.Length < 32)
            {
                byte[] paddedKey = new byte[32];
                Buffer.BlockCopy(keyBytes, 0, paddedKey, 0, keyBytes.Length);
                return paddedKey;
            }
            return keyBytes.Take(32).ToArray();
        }

        private byte[] getIV(string iv)
        {
            if (string.IsNullOrWhiteSpace(iv))
            {
                return new byte[16];
            }
            return Encoding.UTF8.GetBytes(iv);
        }
    }
}
