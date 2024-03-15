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
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;

namespace Jpki.Test.Security.Cryptography
{
    public abstract class TestRSAExtensions
    {
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


        private const string SubjectPublicKeyInfoPem =
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

        private const string EccSubjectPublicKeyInfoPem =
            @"-----BEGIN PUBLIC KEY-----
            MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAACGNU1rVGpVfFyfPlx4Ydz0pQ0N
            2BCrIQpSccUmJbg6v1WYfYZNR9RAQuaONRAla0dhLC6NZ7oslIEW8iNdjA==
            -----END PUBLIC KEY-----";

        protected abstract RSA CreateKey();

        private static void AssertPublicKeysEqual(RSA expected, RSA actual)
        {
            AssertThat.IsTrue(Enumerable.SequenceEqual(
                expected.ExportParameters(false).Modulus!,
                actual.ExportParameters(false).Modulus!));
            AssertThat.IsTrue(Enumerable.SequenceEqual(
                expected.ExportParameters(false).Exponent!,
                actual.ExportParameters(false).Exponent!));
        }

        //---------------------------------------------------------------------
        // Ex/ImportSubjectPublicKeyInfo.
        //---------------------------------------------------------------------

        [Test]
        public void WhenKeyValid_ThenExportSubjectPublicKeyInfoReturnsDerBlob()
        {
            using (var originalKey = CreateKey())
            {
                var subjectPublicKeyInfoDer = originalKey.ExportSubjectPublicKeyInfo();

                using (var reimportedKey = CreateKey())
                {
                    reimportedKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfoDer, out var _);
                    AssertPublicKeysEqual(originalKey, reimportedKey);
                }
            }
        }

        [Test]
        public void WhenDerIsSubjectPublicKeyInfo_ThenImportSubjectPublicKeyInfoThrowsException()
        {
            using (var originalKey = CreateKey())
            {
                var subjectPublicKeyInfoDer = originalKey.ExportSubjectPublicKeyInfo();

                using (var reimportedKey = CreateKey())
                {
                    AssertThat.Throws<CryptographicException>(
                        () => reimportedKey.ImportRSAPublicKey(subjectPublicKeyInfoDer, out var _));
                }
            }
        }

        //---------------------------------------------------------------------
        // Ex/ImportRSAPublicKey.
        //---------------------------------------------------------------------

        [Test]
        public void WhenKeyValid_ThenExportRSAPublicKeyReturnsDerBlob()
        {
            using (var originalKey = CreateKey())
            {
                var rsaPublicKeyDer = originalKey.ExportRSAPublicKey();

                using (var reimportedKey = CreateKey())
                {
                    reimportedKey.ImportRSAPublicKey(rsaPublicKeyDer, out var _);
                    AssertPublicKeysEqual(originalKey, reimportedKey);
                }
            }
        }

        [Test]
        public void WhenDerIsRSAPublicKey_ThenImportSubjectPublicKeyInfoThrowsException()
        {
            using (var originalKey = CreateKey())
            {
                var rsaPublicKeyDer = originalKey.ExportRSAPublicKey();

                using (var reimportedKey = CreateKey())
                {
                    AssertThat.Throws<CryptographicException>(
                        () => reimportedKey.ImportSubjectPublicKeyInfo(rsaPublicKeyDer, out var _));
                }
            }
        }

        //---------------------------------------------------------------------
        // ImportFromPem.
        //---------------------------------------------------------------------

        [Test]
        public void WhenPemContainsRSAPublicKey_ThenImportFromPemSucceeds()
        {
            using (var importedKey = CreateKey())
            {
                importedKey.ImportFromPem(RsaPublicKeyPem, out var format);

                AssertThat.AreEqual(PemEnvelope.DataFormat.RsaPublicKey, format);
                var exported = importedKey.ExportPem(format);

                AssertThat.AreEqual(
                    PemEnvelope.Parse(RsaPublicKeyPem),
                    PemEnvelope.Parse(exported));
            }
        }

        [Test]
        public void WhenPemContainsSubjectPublicKeyInfo_ThenImportFromPemSucceeds()
        {
            using (var importedKey = CreateKey())
            {
                importedKey.ImportFromPem(SubjectPublicKeyInfoPem, out var format);

                AssertThat.AreEqual(PemEnvelope.DataFormat.SubjectPublicKeyInfo, format);
                var exported = importedKey.ExportPem(format);

                AssertThat.AreEqual(
                    PemEnvelope.Parse(SubjectPublicKeyInfoPem),
                    PemEnvelope.Parse(exported));
            }
        }

        [Test]
        public void WhenPemContainsEccPublicKey_ThenImportFromPemThrowsException()
        {
            using (var key = CreateKey())
            {
                AssertThat.Throws<CryptographicException>(
                    () => key.ImportFromPem(EccSubjectPublicKeyInfoPem, out var format));
            }
        }

        //---------------------------------------------------------------------
        // ExportSubjectPublicKeyInfoPem.
        //---------------------------------------------------------------------

        [Test]
        public void ExportSubjectPublicKeyInfoPem()
        {
            using (var originalKey = CreateKey())
            {
                var pem = originalKey.ExportSubjectPublicKeyInfoPem();

                using (var importedKey = CreateKey())
                {
                    importedKey.ImportFromPem(pem, out var format);
                    AssertThat.AreEqual(PemEnvelope.DataFormat.SubjectPublicKeyInfo, format);
                }
            }
        }

        //---------------------------------------------------------------------
        // ExportRSAPublicKeyPem.
        //---------------------------------------------------------------------

        [Test]
        public void ExportRSAPublicKeyPem()
        {
            using (var originalKey = CreateKey())
            {
                var pem = originalKey.ExportRSAPublicKeyPem();

                using (var importedKey = CreateKey())
                {
                    importedKey.ImportFromPem(pem, out var format);
                    AssertThat.AreEqual(PemEnvelope.DataFormat.RsaPublicKey, format);
                }
            }
        }
    }

#if WINDOWS
    [TestFixture]
    public class TestRSAExtensions_CNG : TestRSAExtensions
    {
        protected override RSA CreateKey()
        {
            return new RSACng();
        }
    }

    [TestFixture]
    public class TestRSAExtensions_CryptoServiceProvicer : TestRSAExtensions
    {
        protected override RSA CreateKey()
        {
            return new RSACryptoServiceProvider();
        }
    }

#else

    [TestFixture]
    public class TestRSAExtensions_CryptoServiceProvicer : TestRSAExtensions
    {
        protected override RSA CreateKey()
        {
            return RSA.Create();
        }
    }
#endif
}
