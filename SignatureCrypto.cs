using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace TPLib.Crypto
{
    public class SignatureCrypto : CryptoBase
    {
        /// <summary>
        /// 创建数字签名密钥对
        /// </summary>
        /// <returns>返回字典公私钥 Key值：PublicKey|PrivateKey</returns>
        public static Dictionary<string, byte[]> CreateKeysPair()
        {
            Dictionary<string, byte[]> dict = new Dictionary<string, byte[]>();
            RsaKeyPairGenerator keyGenerator = new RsaKeyPairGenerator();
            RsaKeyGenerationParameters param = new RsaKeyGenerationParameters(BigInteger.ValueOf(3),new SecureRandom(),1024,25);
            //用参数初始化密钥构造器   
            keyGenerator.Init(param);
            AsymmetricCipherKeyPair keyPair = keyGenerator.GenerateKeyPair();
            //获取公钥 
            AsymmetricKeyParameter publicKey = keyPair.Public;
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
            byte[] pub = publicKeyInfo.ToAsn1Object().GetEncoded();
            dict.Add("PublicKey", pub);
            //获取私钥 
            AsymmetricKeyParameter privateKey = keyPair.Private;
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
            byte[] pri = privateKeyInfo.ToAsn1Object().GetEncoded();
            dict.Add("PrivateKey", pri);
            return dict;
        }


        public byte[] PublicKey;
        public byte[] PrivateKey;
    

        public SignatureCrypto(string publicKey,string privateKey)
        {
            try
            {
                PublicKey = Convert.FromBase64String(publicKey);
                PrivateKey = Convert.FromBase64String(privateKey);
            }
            catch (Exception ex)
            {
                OnCryptoErrorEvent(ex);
            }
        }

        /// <summary>
        /// 公钥验证数字签名(MD5withRSA)
        /// </summary>
        /// <param name="inputData">明文</param>
        /// <param name="signature">数字签名</param>
        /// <returns></returns>
        public bool VerifySignature(byte[] inputData, byte[] signature)
        {
            try
            {
                AsymmetricKeyParameter pubKey = PublicKeyFactory.CreateKey(PublicKey);
                var signer = SignerUtilities.GetSigner("MD5withRSA");
                signer.Init(false, pubKey);
                signer.BlockUpdate(inputData, 0, inputData.Length);
                return signer.VerifySignature(signature);
            }
            catch (Exception ex)
            {
                OnCryptoErrorEvent(ex);
                return false;
            }
          
        }

        /// <summary>
        /// 私钥创建数字签名(MD5withRSA)
        /// </summary>
        /// <param name="plainText">明文</param>
        /// <returns></returns>
        public byte[] GetSignature(string plainText)
        {
            try
            {
                AsymmetricKeyParameter privKey = PrivateKeyFactory.CreateKey(PrivateKey);
                var inputData = Encoding.GetEncoding("GBK").GetBytes(plainText);
                var signer = SignerUtilities.GetSigner("MD5withRSA");
                signer.Init(true, privKey);
                signer.BlockUpdate(inputData, 0, inputData.Length);
                return signer.GenerateSignature();
            }
            catch (Exception ex)
            {
                OnCryptoErrorEvent(ex);
                return null;
            }
        }


    

    }
}
