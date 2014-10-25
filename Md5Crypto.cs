using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace TPLib.Crypto
{
    public class Md5Crypto : CryptoBase
    {
        /// <summary>
        /// Md5 散列
        /// </summary>
        /// <param name="sourceStr">原字符串</param>
        /// <returns>Base64String</returns>
        public string Md5Encrypt(string sourceStr)
        {
            
            string result = string.Empty;
            try
            {
                MD5 m = new MD5CryptoServiceProvider();
                byte[] code = m.ComputeHash(Encoding.UTF8.GetBytes(sourceStr));
                if (code != null && code.Length > 0)
                {
                    result = Convert.ToBase64String(code);
                }
            }
            catch (Exception ex)
            {
                
               OnCryptoErrorEvent(ex);
            }
         
            return result;
        }
    }
}
