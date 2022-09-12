using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SafeDevelopment_Lesson5
{
    public class CertificateGenerationProvider
    {
        public void GenerateRootCertificate(CertificateConfiguration settings)
        {
            SecureRandom secRand = new SecureRandom();
            RsaKeyPairGenerator keyGen = new RsaKeyPairGenerator();
            RsaKeyGenerationParameters prms = new RsaKeyGenerationParameters(new Org.BouncyCastle.Math.BigInteger("10001", 16), secRand, 1024, 4);
            keyGen.Init(prms);
            AsymmetricCipherKeyPair keyPair = keyGen.GenerateKeyPair();

            string issuer = "CN=" + settings.CertName;
            string p12FileName = settings.OutFolder + @"\" + settings.CertName + ".p12";
            string crtFileName = settings.OutFolder + @"\" + settings.CertName + ".crt";

            byte[] serialNumber = Guid.NewGuid().ToByteArray();
            serialNumber[0] = (byte)(serialNumber[0] & 0x7F);

            X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
            certGen.SetSerialNumber(new Org.BouncyCastle.Math.BigInteger(1, serialNumber));
            certGen.SetIssuerDN(new X509Name(issuer));
            certGen.SetNotBefore(DateTime.Now.ToUniversalTime());
            certGen.SetNotAfter(DateTime.Now.ToUniversalTime() + new TimeSpan(settings.CertDuration * 365, 0, 0, 0));
            certGen.SetSubjectDN(new X509Name(issuer));
            certGen.SetPublicKey(keyPair.Public);
            certGen.SetSignatureAlgorithm("MD5WITHRSA");
            certGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
                new AuthorityKeyIdentifierStructure(keyPair.Public));
            certGen.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
                new SubjectKeyIdentifierStructure(keyPair.Public));
            certGen.AddExtension(X509Extensions.BasicConstraints, false,
                new BasicConstraints(true));

            Org.BouncyCastle.X509.X509Certificate rootCert = certGen.Generate(keyPair.Private);

            byte[] rawCert = rootCert.GetEncoded();
            
            try
            {
                using (FileStream fs = new FileStream(p12FileName, FileMode.Create))
                {
                    Pkcs12Store p12 = new Pkcs12Store();
                    X509CertificateEntry certEntry = new X509CertificateEntry(rootCert);
                    p12.SetKeyEntry(settings.CertName, new AsymmetricKeyEntry(keyPair.Private),
                        new X509CertificateEntry[] { certEntry });
                    p12.Save(fs, settings.Password.ToCharArray(), secRand);
                    fs.Close();
                }
            }
            catch (Exception exception)
            {                
                throw new CertificateGenerationException("При сохранении закрытой части сертификата произошла ошибка.\r\n" +
                    exception.Message);
            }

            try
            {
                using (FileStream fs = new FileStream(crtFileName, FileMode.Create))
                {
                    fs.Write(rawCert, 0, rawCert.Length);
                    fs.Close();
                }
            }
            catch (Exception exception)
            {                
                throw new CertificateGenerationException("При сохранении открытой части сертификата произошла ошибка.\r\n" +
                    exception.Message);
            }
        }

        public void GenerateCertificate(CertificateConfiguration settings)
        {
            Org.BouncyCastle.X509.X509Certificate rootCertificateInternal =
                DotNetUtilities.FromX509Certificate(settings.RootCertificate);

            SecureRandom secRand = new SecureRandom();
            RsaKeyPairGenerator keyGen = new RsaKeyPairGenerator();
            RsaKeyGenerationParameters prms = new RsaKeyGenerationParameters(new Org.BouncyCastle.Math.BigInteger("10001", 16), secRand, 1024, 4);
            keyGen.Init(prms);
            AsymmetricCipherKeyPair keyPair = keyGen.GenerateKeyPair();

            string subject = "CN=" + settings.CertName;

            string p12FileName = settings.OutFolder + @"\" + settings.CertName + ".p12";
            string crtFileName = settings.OutFolder + @"\" + settings.CertName + ".crt";

            byte[] serialNumber = Guid.NewGuid().ToByteArray();
            serialNumber[0] = (byte)(serialNumber[0] & 0x7F);

            X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
            certGen.SetSerialNumber(new Org.BouncyCastle.Math.BigInteger(1, serialNumber));
            certGen.SetIssuerDN(rootCertificateInternal.IssuerDN);
            certGen.SetNotBefore(DateTime.Now.ToUniversalTime());

            DateTime notAfter = new DateTime();
            certGen.SetNotAfter(DateTime.Now.AddDays(100));
            certGen.SetSubjectDN(new X509Name(subject));
            certGen.SetPublicKey(keyPair.Public);
            certGen.SetSignatureAlgorithm("MD5WITHRSA");
            

            certGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
                new AuthorityKeyIdentifierStructure(rootCertificateInternal.GetPublicKey()));
            certGen.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
                new SubjectKeyIdentifierStructure(keyPair.Public));
            KeyUsage keyUsage = new KeyUsage(settings.CertName.EndsWith("CA") ? 182 : 176);
            certGen.AddExtension(X509Extensions.KeyUsage, true, keyUsage);
            ArrayList keyPurposes = new ArrayList();
            keyPurposes.Add(KeyPurposeID.IdKPServerAuth);
            keyPurposes.Add(KeyPurposeID.IdKPCodeSigning);
            keyPurposes.Add(KeyPurposeID.IdKPEmailProtection);
            keyPurposes.Add(KeyPurposeID.IdKPClientAuth);
            certGen.AddExtension(X509Extensions.ExtendedKeyUsage, true,
                new ExtendedKeyUsage(keyPurposes));
            if (settings.CertName.EndsWith("CA"))
            {
                certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
            }
            
            FieldInfo fi = typeof(X509V3CertificateGenerator).GetField("tbsGen", BindingFlags.NonPublic | BindingFlags.Instance);
            V3TbsCertificateGenerator v3TbsCertificateGenerator = (V3TbsCertificateGenerator)fi.GetValue(certGen);
            TbsCertificateStructure tbsCert = v3TbsCertificateGenerator.GenerateTbsCertificate();


            MD5 md5 = new MD5CryptoServiceProvider();
            byte[] tbsCertHash = md5.ComputeHash(tbsCert.GetDerEncoded());
            
            RSAPKCS1SignatureFormatter signer = new RSAPKCS1SignatureFormatter();
            signer.SetHashAlgorithm("MD5");
            signer.SetKey(settings.RootCertificate.PrivateKey);

            byte[] certSignature = signer.CreateSignature(tbsCertHash);
            
            Org.BouncyCastle.X509.X509Certificate signedCertificate =
                new Org.BouncyCastle.X509.X509Certificate(
                    new X509CertificateStructure(tbsCert,
                        new AlgorithmIdentifier(PkcsObjectIdentifiers.MD5WithRsaEncryption),
                        new DerBitString(certSignature)));
            try
            {
                using (FileStream fs = new FileStream(p12FileName, FileMode.Create))
                {
                    Pkcs12Store p12 = new Pkcs12Store();
                    X509CertificateEntry certEntry = new X509CertificateEntry(signedCertificate);
                    X509CertificateEntry rootCertEntry = new X509CertificateEntry(rootCertificateInternal);
                    p12.SetKeyEntry(settings.CertName, new AsymmetricKeyEntry(keyPair.Private),
                        new X509CertificateEntry[] { certEntry, rootCertEntry });
                    p12.Save(fs, settings.Password.ToCharArray(), secRand);
                    fs.Close();
                }
            }
            catch (Exception exception)
            {
                throw new CertificateGenerationException("При сохранении закрытой части сертификата произошла ошибка.\r\n" +
                    exception.Message);
            }

        }
    }
}
