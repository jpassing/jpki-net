using Jpki.Powershell.Security.Cryptography;
using Jpki.Powershell.Test.Runtime;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Jpki.Powershell.Test.Security.Cryptography
{
    [TestFixture]
    public class TestConvertCertificateFromPem
    {
        private const string CertificatePem =
            @"-----BEGIN CERTIFICATE-----
            MIIB+jCCAWOgAwIBAgIUa/+VBrWwGQfeDOoRJTZuLmkdcxEwDQYJKoZIhvcNAQEL
            BQAwDzENMAsGA1UEAwwEdGVzdDAeFw0yMzEwMzAwODE4MDVaFw0yMzEwMzEwODE4
            MDVaMA8xDTALBgNVBAMMBHRlc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGB
            ALBquZdaJVLykbNhfzxpjl7voRmhmxQlGZo4JkCKmExBYSQMBz16KXg7R1SMF0Yh
            PF39E9IglcyDJan8gUNAn065IFseeuhfcZ8x7vU9KiYTr+T3IzgvVCvWKimltpA5
            KDpy+TthDV83nxaAHF02jkWsFHzBU9VsLbELL8SAW6BDAgMBAAGjUzBRMB0GA1Ud
            DgQWBBRL2VMqPGzO1c6SbGPHJ53O44tPHDAfBgNVHSMEGDAWgBRL2VMqPGzO1c6S
            bGPHJ53O44tPHDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4GBABmb
            v1HASwV9RplDMU4LuuMv5fOLbL3sy04ROcc4ycys8QFQKGtKA+nWrWHoPp9Y7qM2
            tzP5EGpo7mvyFyB9sao6r/SIA/rhXcffVUPUZTjrU7ltC3hd14z74QXTwZci5W/8
            T6i18XNKoNpxi12p/CEh83Ln1rR2ZNmcRUmRMNKc
            -----END CERTIFICATE-----";

        [Test]
        public void WhenPemIsEmptyOrMalformed_CmdletThrowsException(
            [Values("", "----", "-----BEGIN RSA PUBLIC KEY-----\n")] string pem)
        {
            var cmdlet = new ConvertCertificateFromPem()
            {
                Pem = pem
            };

            CmdletAssert.ThrowsException<CryptographicException>(cmdlet);
        }

        [Test]
        public void WhenPemValid_CmdletReturnsCertificate()
        {
            var cmdlet = new ConvertCertificateFromPem()
            {
                Pem = CertificatePem
            };

            CmdletAssert.WritesSingleObject<X509Certificate2>(cmdlet);
        }
    }
}
