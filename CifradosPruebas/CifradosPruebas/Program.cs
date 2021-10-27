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
            string cadena = "3e6f15a4fc73aaa7a95212bd910df36676f3814894128b23f71b26ee9a364b01-6";
            string pass= "KujIDA6573#muxiG20211027";
            //string intIV = "'AES-256-CBC'";

            string salida = encryptAES256CBC(cadena, pass);
            Console.WriteLine("Token: " + salida);
        }


        public static string encryptAES256CBC(string Cadena, string pass)
        {

            // Recrear
            string token_encode;
            var key = new byte[32];

            key = Encoding.UTF8.GetBytes(pass);

            byte[] iv = new byte[16] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            Aes aesAlg = Aes.Create();


            using ((aesAlg))
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;
                aesAlg.Mode = CipherMode.CBC;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                MemoryStream msEncrypt = new MemoryStream();

                using ((msEncrypt))
                {
                    CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
                    using ((csEncrypt))
                    {
                        StreamWriter swEncrypt = new StreamWriter(csEncrypt);
                        using ((swEncrypt))
                            swEncrypt.Write(Cadena);
                        byte[] encrypted;
                        encrypted = msEncrypt.ToArray();

                        string Encrypt = Convert.ToBase64String(encrypted);
                        token_encode = Encrypt;//Uri.EscapeDataString(Encrypt);
                    }
                }
            }

            return token_encode;
        }




    }
}
