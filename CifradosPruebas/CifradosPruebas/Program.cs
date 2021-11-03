using AES256;
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
            string textToEncrypt = "6-6";
            string password = "KujIDA6573#muxiG20211103";
            string iv = string.Empty;
            string result = new AES256CBCEncrypter().Encrypt(textToEncrypt, password, iv);
            Console.WriteLine($"Text to encrypt: {textToEncrypt}");
            Console.WriteLine($"Password: {password}");
            Console.WriteLine($"IV: {iv}");
            Console.WriteLine(result);
            Console.ReadKey();

        }

    } 
}