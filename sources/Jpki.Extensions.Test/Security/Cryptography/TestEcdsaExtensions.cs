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
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Jpki.Test.Security.Cryptography
{
    [TestFixture]
    public class TestEcdsaExtensions
    {
        private static readonly byte[] Data = Encoding.ASCII.GetBytes(
            "The quick brown fox jumps over the lazy dog");


        private const string SubjectPublicKeyInfoPem =
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

        private static void AssertPublicKeysEqual(ECDsa expected, ECDsa actual)
        {
            var expectedParameters = expected.ExportParameters(false);
            var actualParameters = actual.ExportParameters(false);

            Assert.AreEqual(
                expectedParameters.Curve.CurveType,
                actualParameters.Curve.CurveType);
            Assert.IsTrue(Enumerable.SequenceEqual(
                expectedParameters.Q.X!,
                actualParameters.Q.X!));
            Assert.IsTrue(Enumerable.SequenceEqual(
                expectedParameters.Q.Y!,
                actualParameters.Q.Y!));
        }

        //---------------------------------------------------------------------
        // Sign/verify.
        //---------------------------------------------------------------------

        [Test]
        public void SignVerifyDataArray(
            [Values(
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation,
                DSASignatureFormat.Rfc3279DerSequence)] DSASignatureFormat format)
        {
            using (var key = ECDsaCng.Create())
            {
                var signature = key.SignData(
                    Data,
                    HashAlgorithmName.SHA256,
                    format);
                Assert.IsTrue(key.VerifyData(
                    Data,
                    signature,
                    HashAlgorithmName.SHA256,
                    format));
            }
        }

        [Test]
        public void SignVerifyDataArrayWithIndex(
            [Values(
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation,
                DSASignatureFormat.Rfc3279DerSequence)] DSASignatureFormat format)
        {
            using (var key = ECDsaCng.Create())
            {
                var signature = key.SignData(
                    Data,
                    0,
                    Data.Length,
                    HashAlgorithmName.SHA256,
                    format);
                Assert.IsTrue(key.VerifyData(
                    Data,
                    0,
                    Data.Length,
                    signature,
                    HashAlgorithmName.SHA256,
                    format));
            }
        }

        [Test]
        public void SignVerifyDataStream(
            [Values(
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation,
                DSASignatureFormat.Rfc3279DerSequence)] DSASignatureFormat format)
        {
            using (var stream = new MemoryStream())
            using (var key = ECDsaCng.Create())
            {
                stream.Write(Data, 0, Data.Length);

                stream.Seek(0, SeekOrigin.Begin);
                var signature = key.SignData(
                    stream,
                    HashAlgorithmName.SHA256,
                    format);

                stream.Seek(0, SeekOrigin.Begin);
                Assert.IsTrue(key.VerifyData(
                    stream,
                    signature,
                    HashAlgorithmName.SHA256,
                    format));
            }
        }

        //---------------------------------------------------------------------
        // Ex/ImportSubjectPublicKeyInfo.
        //---------------------------------------------------------------------

        [Test]
        public void WhenKeyValid_ThenExportSubjectPublicKeyInfoReturnsDerBlob(
            [Values(256, 384, 521)] int keySize)
        {
            using (var originalKey = new ECDsaCng(keySize))
            {
                var subjectPublicKeyInfoDer = originalKey.ExportSubjectPublicKeyInfo();

                using (var reimportedKey = new ECDsaCng())
                {
                    reimportedKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfoDer, out var _);
                    AssertPublicKeysEqual(originalKey, reimportedKey);
                }
            }
        }

        //---------------------------------------------------------------------
        // ImportFromPem.
        //---------------------------------------------------------------------

        [Test]
        public void WhenPemContainsSubjectPublicKeyInfo_ThenImportFromPemSucceeds(
            [Values(256, 384, 521)] int keySize)
        {
            using (var importedKey = new ECDsaCng(keySize))
            {
                importedKey.ImportFromPem(SubjectPublicKeyInfoPem);

                var exported = importedKey.ExportSubjectPublicKeyInfoPem();

                Assert.AreEqual(
                    PemEnvelope.Parse(SubjectPublicKeyInfoPem),
                    PemEnvelope.Parse(exported));
            }
        }

        [Test]
        public void WhenPemContainsRsaPublicKey_ThenImportFromPemThrowsException()
        {
            using (var importedKey = new ECDsaCng())
            {
                Assert.Throws<CryptographicException>(
                    () => importedKey.ImportFromPem(RsaSubjectPublicKeyInfoPem));
            }
        }

        //---------------------------------------------------------------------
        // ExportSubjectPublicKeyInfoPem.
        //---------------------------------------------------------------------

        [Test]
        public void ExportSubjectPublicKeyInfoPem()
        {
            using (var originalKey = new ECDsaCng())
            {
                var pem = originalKey.ExportSubjectPublicKeyInfoPem();

                using (var importedKey = new ECDsaCng())
                {
                    importedKey.ImportFromPem(pem);
                }
            }
        }
    }
}
