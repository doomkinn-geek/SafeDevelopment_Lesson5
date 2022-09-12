using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
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
        }
    }
}
