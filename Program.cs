using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Rsa_Conv
{
    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length > 0)
            {
                if (args[0].ToLower().EndsWith(".xml") && File.Exists(args[0]))
                {
                    Console.WriteLine(XmlToPem(File.ReadAllText(args[0])));
                }
                else if (args[0].ToLower().EndsWith(".pem") && File.Exists(args[0]))
                {
                    Console.WriteLine(PemToXml(File.ReadAllText(args[0])));
                }
                else
                {
                    Console.WriteLine("Usage: XmlPemConverter key.pem or XmlPemCoverter key.xml");
                }
            }
            else
            {
                Console.WriteLine("Usage: XmlPemConverter key.pem or XmlPemCoverter key.xml");
            }
        }

        static string XmlToPem(String xml)
        {
            using var rsa = RSA.Create();
            rsa.FromXmlString(xml);

            var keyPair = DotNetUtilities.GetRsaKeyPair(rsa);
            if (keyPair != null)
            {
                PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
                return FormatPem(Convert.ToBase64String(privateKeyInfo.GetEncoded()), "RSA PRIVATE KEY");
            }

            var publicKey = DotNetUtilities.GetRsaPublicKey(rsa);
            if (publicKey is null)
            {
                throw new InvalidKeyException("Invalid RSA XML Key.");
            }

            var publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);

            return FormatPem(Convert.ToBase64String(publicKeyInfo.GetEncoded()), "PUBLIC KEY");
        }

        static string PemToXml(String pem)
        {
            if (pem.StartsWith("-----BEGIN RSA PRIVATE KEY-----") || pem.StartsWith("-----BEGIN PRIVATE KEY-----"))
            {
                return GetXmlRsaKey(pem, obj =>
                {
                    if ((obj as RsaPrivateCrtKeyParameters) != null)
                        return DotNetUtilities.ToRSA((RsaPrivateCrtKeyParameters)obj);
                    var keyPair = (AsymmetricCipherKeyPair)obj;
                    return DotNetUtilities.ToRSA((RsaPrivateCrtKeyParameters)keyPair.Private);
                }, rsa => rsa.ToXmlString(true));
            }

            if (pem.StartsWith("-----BEGIN RSA PUBLIC KEY-----") || pem.StartsWith("-----BEGIN PUBLIC KEY-----"))
            {
                return GetXmlRsaKey(pem, obj =>
                {
                    var publicKey = (RsaKeyParameters)obj;
                    return DotNetUtilities.ToRSA(publicKey);
                }, rsa => rsa.ToXmlString(false));
            }

            throw new InvalidKeyException("Unsupported PEM format.");
        }

        static string GetXmlRsaKey(String pem, Func<Object, RSA> getRsa, Func<RSA, String> getKey)
        {
            using var ms = new MemoryStream();
            using var sw = new StreamWriter(ms);
            using var sr = new StreamReader(ms);
            sw.Write(pem);
            sw.Flush();
            ms.Position = 0;
            var pr = new PemReader(sr);
            object keyPair = pr.ReadObject();

            using RSA rsa = getRsa(keyPair);
            var xml = getKey(rsa);

            return xml;
        }

        static string FormatPem(String pem, String keyType)
        {
            var sb = new StringBuilder();
            sb.Append($"-----BEGIN {keyType}-----\n");

            var line = 1;
            var width = 64;

            while ((line - 1) * width < pem.Length)
            {
                Int32 startIndex = (line - 1) * width;
                Int32 len = line * width > pem.Length ? pem.Length - startIndex : width;
                sb.Append($"{pem.Substring(startIndex, len)}\n");
                line++;
            }

            sb.Append($"-----END {keyType}-----\n");

            return sb.ToString();
        }
    }
}
