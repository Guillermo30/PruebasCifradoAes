using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CifradosPruebas
{
    class Program
    {
        static void Main(string[] args)
        {
            //string cadena = "3e6f15a4fc73aaa7a95212bd910df36676f3814894128b23f71b26ee9a364b01";
            string cadena = "6-6";
            string pass = "KujIDA6573#muxiG20211102";
            String valorSalida = "vrOQ1V4YQ6X1ZmBFCOIyfw==";
            //string pass2 = Convert.ToBase64String(Encoding.UTF8.GetBytes(pass));

            //string recta = "vrOQ1V4YQ6X1ZmBFCOIyfw==";
            //string recta = "zLC6y4tL+WxKgC9hp48smg==";

            //string recta = Aes256Encrypt(cadena, pass);
            //string retb = Aes256Decrypt(recta, pass);

            string recta = Encrypt(cadena);
            //string recta2 = "vrOQ1V4YQ6X1ZmBFCOIyfw==";

            //AES.EncryptString(cadena, pass, "00000000000000000000000000000000");
            //string retb2 = AES.Decrypt(recta2, pass, "0000000000000000");

        }

        public static string Encrypt(string clearText)
        {
            string EncryptionKey = "KujIDA6573#muxiG20211102";
            byte[] clearBytes = ASCIIEncoding.UTF8.GetBytes(clearText);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new
                    Rfc2898DeriveBytes(EncryptionKey, new byte[]
                    { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(clearBytes, 0, clearBytes.Length);
                        cs.Close();
                    }
                    clearText = Convert.ToBase64String(ms.ToArray());
                }
            }
            return clearText;
        }

        public static string Aes256Encrypt(string input, string password)
        {
            using (var aes = new RijndaelManaged())
            {
               
                aes.Mode = CipherMode.CBC;
                aes.BlockSize = 128;
                aes.KeySize = 256;
                aes.Padding = PaddingMode.PKCS7;
                aes.IV = new byte[16] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

                if (password.Length > 16)
                    password = password.Substring(0, 16);

                byte[] pwd = Encoding.UTF8.GetBytes(password);
                aes.Key = pwd;

                byte[] bytesToBeEncrypted = Encoding.UTF8.GetBytes(input);

                using (MemoryStream ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, aes.CreateEncryptor(aes.Key, aes.IV), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                    }
                    var msArray = ms.ToArray();
                    return Convert.ToBase64String(msArray);
                }
            }
        }

        public static string Aes256Decrypt(string input, string password)
        {
            using (var aes = new RijndaelManaged())
            {
                aes.GenerateIV();
                aes.Mode = CipherMode.CBC;
                aes.BlockSize = 128;
                aes.KeySize = 256;
                aes.Padding = PaddingMode.PKCS7;
                aes.IV = new byte[16] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

                if (password.Length > 16)
                    password = password.Substring(0, 16);

                byte[] pwd = Encoding.UTF8.GetBytes(password);
                aes.Key = pwd;

                byte[] bytesToBeDecrypted = Convert.FromBase64String(input);

                using (MemoryStream ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, aes.CreateDecryptor(aes.Key, aes.IV), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                    }
                    var msArray = ms.ToArray();
                    return Encoding.UTF8.GetString(msArray, 0, msArray.Length);
                }
            }
        }


    }
}
