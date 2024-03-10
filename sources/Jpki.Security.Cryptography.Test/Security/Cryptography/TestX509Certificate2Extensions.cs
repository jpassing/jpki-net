//
// Copyright 2023 Johannes Passing
//
// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
// 
//   http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
//

using Jpki.Security.Cryptography;
using NUnit.Framework;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Jpki.Test.Security.Cryptography
{
    [TestFixture]
    public class TestX509Certificate2Extensions
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

        private const string EcdsaSubjectPublicKeyInfoPem =
            @"-----BEGIN PUBLIC KEY-----
            MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEWgzIKidlfb9gXYdE8ds6nOB+BS3OiRJ1
            qtmuL5VNyfL6mewC6emEAIwJ0/RmhrPMudwFk2ikpqFSyD3GTJ9aFg==
            -----END PUBLIC KEY-----";

        //---------------------------------------------------------------------
        // CreateFromPem.
        //---------------------------------------------------------------------

        [Test]
        public void WhenPemNullOrEmpty_ThenCreateFromPemThrowsExxeption(
            [Values(null, "", " ")] string pem)
        {
            Assert.Throws<CryptographicException>(
                () => X509Certificate2Extensions.CreateFromPem(pem));
        }

        [Test]
        public void WhenPemMalformed_ThenCreateFromPemThrowsExxeption(
            [Values(1, 10, 100)] int limit)
        {
            Assert.Throws<CryptographicException>(
                () => X509Certificate2Extensions.CreateFromPem(CertificatePem.Substring(0, limit)));
        }

        [Test]
        public void WhenPemContainsCertificate_ThenCreateFromPemSucceeds()
        {
            var certificate = X509Certificate2Extensions.CreateFromPem(CertificatePem);
            AssertThat.AreEqual("CN=test", certificate.Subject);
        }

        [Test]
        public void WhenPemDoesNotContainsCertificate_ThenCreateFromPemThrowsException()
        {
            AssertThat.Throws<CryptographicException>(
                () => X509Certificate2Extensions.CreateFromPem(EcdsaSubjectPublicKeyInfoPem));
        }

        //---------------------------------------------------------------------
        // ExportCertificatePem.
        //---------------------------------------------------------------------

        [Test]
        public void ExportCertificatePem()
        {
            var original = X509Certificate2Extensions.CreateFromPem(CertificatePem);

            var reimported = X509Certificate2Extensions.CreateFromPem(
                original.ExportCertificatePem());

            AssertThat.AreEqual(original.SerialNumber, reimported.SerialNumber);
            AssertThat.AreEqual(original.Thumbprint, reimported.Thumbprint);
        }

        //---------------------------------------------------------------------
        // TryGetExtension.
        //---------------------------------------------------------------------

#if NET6_0_OR_GREATER
        private X509Certificate2 CreateCertificate(RSA key)
        {
            var request = new CertificateRequest(
                "CN=Test",
                key,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(
                new X509BasicConstraintsExtension());
            return request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddHours(-1),
                DateTimeOffset.UtcNow.AddHours(1));
        }

        [Test]
        public void WhenExtensionPresent_ThenTryGetExtensionSucceeds()
        {
            using (var key = RSACng.Create())
            {
                var certificate = CreateCertificate(key);

                AssertThat.IsTrue(certificate.TryGetExtension(
                    Oids.BasicConstraints, 
                    out var extension));
                AssertThat.IsNotNull(extension);
            }
        }

        [Test]
        public void WhenExtensionMissing_ThenTryGetExtensionReturnsFalse()
        {
            using (var key = RSACng.Create())
            {
                var certificate = CreateCertificate(key);

                AssertThat.IsFalse(certificate.TryGetExtension(
                    Oids.ECC,
                    out var extension));
                AssertThat.IsNull(extension);
            }
        }
#endif
    }
}
