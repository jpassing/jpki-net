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

namespace Jpki.Test.Format
{
    [TestFixture]
    public class TestPemEnvelope
    {
        private const string EcdsaSubjectPublicKeyInfoPem =
            @"-----BEGIN PUBLIC KEY-----
            MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEWgzIKidlfb9gXYdE8ds6nOB+BS3OiRJ1
            qtmuL5VNyfL6mewC6emEAIwJ0/RmhrPMudwFk2ikpqFSyD3GTJ9aFg==
            -----END PUBLIC KEY-----";

        private const string RsaSubjectPublicKeyInfoPem =
            @"-----BEGIN PUBLIC KEY-----
            MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAyItKCYN/yAzDEv2HaDaq
            kK3J5AjerXmP1ZhBa8r5M5xQTkHPnkOkOc1KPly/xH4hmBVf00dfGZ91hTez1iD0
            XKkmfwP4TGXZ1YeqvlS44bvt3yZCR09aA0cGwS5Dp6xFIlz3aahMaV3gXwqaNLxW
            Xy5qJSZLIXhxAd0uqlnudweoMgxMbmq8vSMGmx8U8r3x2ldYhdcDYD+wAJCDGPeI
            vNTcHmFujYH8cMobFjewQcGDtf2lOtHn6Q15h6cuENpI5q6Rl7Xmim+Xq6fwiAf7
            ivRRgtOTncBgBVPhjB6vmtSP1CbF6Mpww/ZPTuavBr3dCKmywBRiVHbndOZWREnB
            gdY3koteVKcIVWwzLwzjPJOX1jTWGdCkX/vs6qFOgfnFOd0mDEywF+AwBAXXADw4
            GxZllq/lzBNf6JWNLsHLQY19ke8doCkc4/C2Gn7+xJKqM/YVWEZxVR+WhqkDCpJV
            wtUlPtOf2x3nNM/kM8p8pZKDU6SWNlbuRgYH2GJa8ZPrAgMBAAE=
            -----END PUBLIC KEY-----";

        private const string RsaPublicKeyPem =
            @"-----BEGIN RSA PUBLIC KEY-----
            MIIBigKCAYEAq3DnhgYgLVJknvDA3clATozPtjI7yauqD4/ZuqgZn4KzzzkQ4BzJ
            ar4jRygpzbghlFn0Luk1mdVKzPUgYj0VkbRlHyYfcahbgOHixOOnXkKXrtZW7yWG
            jXPqy/ZJ/+kFBNPAzxy7fDuAzKfU3Rn50sBakg95pua14W1oE4rtd4/U+sg2maCq
            6HgGdCLLxRWwXA8IBtvHZ48i6kxiz9tucFdS/ULvWsXjQnyE5rgs3tPhptyl2/js
            /6FGgdKDaPal8/tud/rPxYSuzBPp7YwRKRRN1EpYQdd4tZzeXdvOvrSIfH+ZL7Rc
            i+HGasbRjCom3HJL+wDGVggUkeuOUzZDjKGqZNCvZIqe5FuU0NAd8c2w2Mxaxia9
            1G8jZDu92DqCEI/HoxXsZPSjd0L4EMx5HqXpYpFY2YPL95zabmynO3RCTWFN7uq6
            DJGlzRCTHeRDa4CvNwHCzv0kqR4uo6VlWp2dW2M/v0k1+kP70EwGqq9dnK5RMXC3
            XwJbrAbpGUDlAgMBAAE=
            -----END RSA PUBLIC KEY-----";

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

        //---------------------------------------------------------------------
        // Parse.
        //---------------------------------------------------------------------

        [Test]
        public void WhenHeaderMalformed_ThenParseThrowsException()
        {
            AssertThat.Throws<ArgumentException>(() => PemEnvelope.Parse(""));
            AssertThat.Throws<CryptographicException>(() => PemEnvelope.Parse("--"));
            AssertThat.Throws<CryptographicException>(() => PemEnvelope.Parse("-----BEGIN PRIVATE KEY-----"));
        }

        [Test]
        public void WhenHeaderIndicatesRsaPublicKey_ThenParseSucceeds()
        {
            var pem = PemEnvelope.Parse(RsaPublicKeyPem);
            AssertThat.AreEqual(PemEnvelope.DataFormat.RsaPublicKey, pem.Format);
        }

        [Test]
        public void WhenHeaderIndicatesSubjectPublicKeyInfo_ThenParseSucceeds()
        {
            var pem = PemEnvelope.Parse(EcdsaSubjectPublicKeyInfoPem);
            AssertThat.AreEqual(PemEnvelope.DataFormat.SubjectPublicKeyInfo, pem.Format);
        }

        [Test]
        public void WhenHeaderIndicatesCertificate_ThenParseSucceeds()
        {
            var pem = PemEnvelope.Parse(CertificatePem);
            AssertThat.AreEqual(PemEnvelope.DataFormat.Certificate, pem.Format);
        }

        //---------------------------------------------------------------------
        // ToString.
        //---------------------------------------------------------------------

        [Test]
        public void WhenParsed_ThenToStringReturnsOriginal()
        {
            var pem = PemEnvelope.Parse(EcdsaSubjectPublicKeyInfoPem);

            AssertThat.AreEqual(
                "-----BEGIN PUBLIC KEY-----\r\n" +
                "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEWgzIKidlfb9gXYdE8ds6nOB+BS3O" +
                "iRJ1qtmuL5VNyfL6mewC6emEAIwJ0/RmhrPMudwFk2ikpqFSyD3GTJ9aFg==" +
                "\r\n-----END PUBLIC KEY-----",
                pem.ToString());
        }

        //---------------------------------------------------------------------
        // Equals.
        //---------------------------------------------------------------------

        [Test]
        public void WhenOtherIsNullOrDifferentType_ThenEqualsIsFalse()
        {
            var pem = PemEnvelope.Parse(RsaSubjectPublicKeyInfoPem);

            AssertThat.IsFalse(pem.Equals(null));
            AssertThat.IsFalse(pem.Equals(string.Empty));
        }

        [Test]
        public void WhenKeysDifferent_ThenEqualsIsFalse()
        {
            var rsa = PemEnvelope.Parse(RsaSubjectPublicKeyInfoPem);
            var ecdsa = PemEnvelope.Parse(EcdsaSubjectPublicKeyInfoPem);

            AssertThat.IsFalse(rsa.Equals(ecdsa));
            AssertThat.IsFalse(rsa == ecdsa);
            AssertThat.IsTrue(rsa != ecdsa);
        }

        [Test]
        public void WhenKeysEqual_ThenEqualsIsTrue()
        {
            var rsa1 = PemEnvelope.Parse(RsaSubjectPublicKeyInfoPem);
            var rsa2 = PemEnvelope.Parse(RsaSubjectPublicKeyInfoPem);

            AssertThat.IsTrue(rsa1.Equals(rsa2));
            AssertThat.IsTrue(rsa1 == rsa2);
            AssertThat.IsFalse(rsa1 != rsa2);
        }

        [Test]
        public void WhenKeysEqual_ThenGetHashCodeIsEqual()
        {
            var rsa1 = PemEnvelope.Parse(RsaSubjectPublicKeyInfoPem);
            var rsa2 = PemEnvelope.Parse(RsaSubjectPublicKeyInfoPem);

            AssertThat.AreEqual(rsa1.GetHashCode(), rsa2.GetHashCode());
        }
    }
}
