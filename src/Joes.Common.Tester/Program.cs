using System;
using System.IO;
using System.Text;

namespace Joes.Common.Tester
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;

            JsonTester();

            CipherTester();

            Console.ReadKey();
        }

        private static void CipherTester()
        {
            var str = "input 中文 。";

            #region Hash

            Console.WriteLine("--------------------------HASH--------------------------");
            Console.WriteLine(CipherHelper.Hash(str, CipherHelper.HashFormat.MD516));
            Console.WriteLine(CipherHelper.Hash(str, CipherHelper.HashFormat.MD532));
            Console.WriteLine(CipherHelper.Hash(str, CipherHelper.HashFormat.SHA1));
            Console.WriteLine(CipherHelper.Hash(str, CipherHelper.HashFormat.SHA256));
            Console.WriteLine(CipherHelper.Hash(str, CipherHelper.HashFormat.SHA512));

            #endregion

            #region Hmac

            var key = CipherHelper.CreateRandom(64);
            Console.WriteLine("--------------------------HMAC--------------------------");
            Console.WriteLine(CipherHelper.Hmac(str, key, CipherHelper.HmacFormat.HMACMD5));
            Console.WriteLine(CipherHelper.Hmac(str, key, CipherHelper.HmacFormat.HMACSHA1));
            Console.WriteLine(CipherHelper.Hmac(str, key, CipherHelper.HmacFormat.HMACSHA256));
            Console.WriteLine(CipherHelper.Hmac(str, key, CipherHelper.HmacFormat.HMACSHA512));

            #endregion

            #region AES

            Console.WriteLine("--------------------------AES--------------------------");

            key = CipherHelper.CreateRandom(32);

            var iv = CipherHelper.CreateRandom(16);

            var encryptStr = CipherHelper.SymmetricEncrypt(str, CipherHelper.SymmetricFormat.AES, key, iv);

            Console.WriteLine(encryptStr);

            var decryptStr = CipherHelper.SymmetricDecrypt(encryptStr, CipherHelper.SymmetricFormat.AES, key, iv);

            Console.WriteLine(decryptStr);

            Console.WriteLine("解密后的结果与原始结果是否相等：{0}", str == decryptStr);

            #endregion

            #region TripleDES

            Console.WriteLine("--------------------------TripleDES--------------------------");

            key = CipherHelper.CreateRandom(24);

            iv = CipherHelper.CreateRandom(8);

            encryptStr = CipherHelper.SymmetricEncrypt(str, CipherHelper.SymmetricFormat.TripleDES, key, iv);

            Console.WriteLine(encryptStr);

            decryptStr = CipherHelper.SymmetricDecrypt(encryptStr, CipherHelper.SymmetricFormat.TripleDES, key, iv);

            Console.WriteLine(decryptStr);

            Console.WriteLine("解密后的结果与原始结果是否相等：{0}", str == decryptStr);

            #endregion

            #region Rsa

            Console.WriteLine("--------------------------Rsa--------------------------");

            var publicFile = Path.Combine(AppContext.BaseDirectory, "public.key");

            var privateFile = Path.Combine(AppContext.BaseDirectory, "private.key");

            CipherHelper.CreateRsaKeyFile(publicFile, privateFile);

            var publicKey = File.ReadAllText(publicFile);

            var privateKey = File.ReadAllText(privateFile);

            encryptStr = CipherHelper.RsaEncrypt(str, publicKey);

            Console.WriteLine(encryptStr);

            decryptStr = CipherHelper.RsaDecrypt(encryptStr, privateKey);

            Console.WriteLine(decryptStr);

            Console.WriteLine("解密后的结果与原始结果是否相等：{0}", str == decryptStr);

            Console.WriteLine("--------------------------Rsa Signature--------------------------");

            var hash = CipherHelper.RsaSignature(str, privateKey);

            Console.WriteLine(hash);

            Console.WriteLine("验证签名结果：{0}", CipherHelper.RsaVerifySign(str, hash, publicKey));

            #endregion
        }

        private static void JsonTester()
        {
            Console.WriteLine("--------------------------Json--------------------------");

            var obj = new { A = 1, B = "2", C = 3, D = DateTime.Now };

            var str = obj.ToJson(true);

            Console.WriteLine(str);

            dynamic result = str.JsonTo();

            Console.WriteLine(result.D);

            var error = new CustomException("Test Error");

            Console.WriteLine(error.ToJson(false));
        }
    }
}