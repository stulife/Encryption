using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;

namespace TPLib.Crypto
{
    public class DesdeCrypto : CryptoBase
    {

        /// <summary>
        /// Desde 密钥Key
        /// </summary>
        public byte[] DeSedeKey = null;

        /// <summary>
        /// 创建DeSede Key
        /// </summary>
        /// <returns></returns>
        public static string CreateDeSedeKey()
        {
            TripleDESCryptoServiceProvider tdsp = new TripleDESCryptoServiceProvider();
            tdsp.Mode = CipherMode.ECB;
            tdsp.Padding = PaddingMode.PKCS7;
            tdsp.GenerateKey();
            if (tdsp.Key.Length > 0)
            {
                return Convert.ToBase64String(tdsp.Key);
            }
            return string.Empty;
        }

        /// <summary>
        /// Des密码类
        /// </summary>
        /// <param name="desedeKey">DesKey</param>
        public DesdeCrypto(string desedeKey)
        {
            try
            {
                DeSedeKey = Convert.FromBase64String(desedeKey);
            }
            catch (Exception ex)
            {
                OnCryptoErrorEvent(ex);
            }
        }

        /// <summary>
        /// Des密码类
        /// </summary>
        /// <param name="btDesKey">btDesKey</param>
        public DesdeCrypto(byte[] btDesKey)
        {
            try
            {
                DeSedeKey = btDesKey;
            }
            catch (Exception ex)
            {
                OnCryptoErrorEvent(ex);
            }
        }



        /// <summary>
        /// Des密码类(使用默认DesKey)
        /// </summary>
        public DesdeCrypto()
        {
            try
            {
                DeSedeKey = Convert.FromBase64String("BIO7RW69E89+vt0kHIAzWxgO7S+e3ySR");
            }
            catch (Exception ex)
            {
                OnCryptoErrorEvent(ex);
            }
        }

        /// <summary>
        /// 对称加密（DeSede）
        /// </summary>
        /// <param name="data">原文数据</param>
        /// <returns>加密数据</returns>
        public byte[] DeSedeEncrypt(byte[] data)
        {
            try
            {
                if (DeSedeKey == null)
                {
                    throw new Exception("DeSedeKey 为 null");
                }

                TripleDESCryptoServiceProvider des = new TripleDESCryptoServiceProvider();
                des.Key = DeSedeKey;
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.PKCS7;
                ICryptoTransform dEsEncrypt = des.CreateEncryptor();
                return dEsEncrypt.TransformFinalBlock(data, 0, data.Length);

            }
            catch (CryptographicException ex)
            {
                OnCryptoErrorEvent(ex);
                return null;
            }
        }

        /// <summary>
        /// 对称解密（DeSede）
        /// </summary>
        /// <param name="data">加密数据</param>
        /// <returns>原文数据</returns>
        public byte[] DeSedeDecrypt(byte[] data)
        {
            try
            {
                if (DeSedeKey == null)
                {
                    throw new Exception("DeSedeKey 为 null");
                }

                TripleDESCryptoServiceProvider des = new TripleDESCryptoServiceProvider();
                des.Key = DeSedeKey;
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.PKCS7;
                ICryptoTransform dEsEncrypt = des.CreateDecryptor();
                return dEsEncrypt.TransformFinalBlock(data, 0, data.Length);
            }
            catch (CryptographicException ex)
            {
                OnCryptoErrorEvent(ex);
                return null;
            }
        }

        /// <summary>
        /// 对称加密（DES）
        /// </summary>
        /// <param name="key">DES Key</param>
        /// <param name="data">原文数据</param>
        /// <returns>加密数据</returns>
        public virtual byte[] DESEncrypt(byte[] data)
        {
            try
            {
                DESCryptoServiceProvider des = new DESCryptoServiceProvider();
                des.Mode = CipherMode.ECB;
                des.Key = DeSedeKey;
                //des.Padding = PaddingMode.PKCS7;
                //des.IV = key;
                System.IO.MemoryStream ms = new System.IO.MemoryStream();
                using (CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(data, 0, data.Length);
                    cs.FlushFinalBlock();
                    cs.Close();
                }
                return ms.ToArray();
            }
            catch (CryptographicException ex)
            {
                OnCryptoErrorEvent(ex);
                return null;
            }
        }

        /// <summary>
        /// 对称解密（DES）
        /// </summary>
        /// <param name="key">DES Key</param>
        /// <param name="data">加密数据</param>
        /// <returns>原文数据</returns>
        public virtual byte[] DESDecrypt(byte[] data)
        {
            try
            {
                using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
                {
                    des.Key = DeSedeKey;
                    des.Mode = CipherMode.ECB;
                    //des.IV = key;
                    System.IO.MemoryStream ms = new System.IO.MemoryStream();
                    using (CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(data, 0, data.Length);
                        cs.FlushFinalBlock();
                        cs.Close();
                    }
                    byte[] sData = ms.ToArray();
                    ms.Close();
                    return sData;
                }
            }
            catch (CryptographicException ex)
            {
                OnCryptoErrorEvent(ex);
                return null;
            }
        }


    }





}
