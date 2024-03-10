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

using Jpki.Security.Cryptography.Cose;
using NUnit.Framework;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Jpki.Test.Security.Cryptography.Cose
{
    [TestFixture]
    public class TestCoseAlgorithmExtensions
    {
        //---------------------------------------------------------------------
        // GetName.
        //---------------------------------------------------------------------

        [Test]
        public void WhenAlgorithValid_ThenGetNameSucceeds(
            [Values(
                CoseHashAlgorithm.SHA_256,
                CoseHashAlgorithm.SHA_384,
                CoseHashAlgorithm.SHA_512)] CoseHashAlgorithm alg)
        {
            AssertThat.IsNotNull(alg.GetName());
        }

        [Test]
        public void WhenAlgorithInalid_ThenGetNameThrowsException()
        {
            AssertThat.Throws<ArgumentException>(
                () => ((CoseHashAlgorithm)0).GetName());
        }

        //---------------------------------------------------------------------
        // GetHashAlgorithm.
        //---------------------------------------------------------------------

        [Test]
        public void WhenSignatureAlgorithmUsesSha256_ThenGetHashAlgorithmReturnsSha256(
            [Values(
                CoseSignatureAlgorithm.RS256,
                CoseSignatureAlgorithm.PS256,
                CoseSignatureAlgorithm.ES256)] CoseSignatureAlgorithm alg)
        {
            AssertThat.AreEqual(CoseHashAlgorithm.SHA_256, alg.GetHashAlgorithm());
        }

        [Test]
        public void WhenSignatureAlgorithmUsesSha384_ThenGetHashAlgorithmReturnsSha384(
            [Values(
                CoseSignatureAlgorithm.RS384,
                CoseSignatureAlgorithm.PS384,
                CoseSignatureAlgorithm.ES384)] CoseSignatureAlgorithm alg)
        {
            AssertThat.AreEqual(CoseHashAlgorithm.SHA_384, alg.GetHashAlgorithm());
        }

        [Test]
        public void WhenSignatureAlgorithmUsesSha512_ThenGetHashAlgorithmReturnsSha512(
            [Values(
                CoseSignatureAlgorithm.RS512,
                CoseSignatureAlgorithm.PS512,
                CoseSignatureAlgorithm.ES512)] CoseSignatureAlgorithm alg)
        {
            AssertThat.AreEqual(CoseHashAlgorithm.SHA_512, alg.GetHashAlgorithm());
        }

        [Test]
        public void WhenSignatureAlgorithmInvalid_ThenGetHashAlgorithmReturnsSha512()
        {
            AssertThat.Throws<ArgumentException>(
                () => ((CoseSignatureAlgorithm)0).GetHashAlgorithm());
        }

        //---------------------------------------------------------------------
        // GetRSASignaturePadding.
        //---------------------------------------------------------------------

        [Test]
        public void WhenSignatureAlgorithmUsesPkcs1_ThenGetHashAlgorithmReturnPkcs1(
            [Values(
                CoseSignatureAlgorithm.RS256,
                CoseSignatureAlgorithm.RS384,
                CoseSignatureAlgorithm.RS512)] CoseSignatureAlgorithm alg)
        {
            AssertThat.AreEqual(RSASignaturePadding.Pkcs1, alg.GetRSASignaturePadding());
        }

        [Test]
        public void WhenSignatureAlgorithmUsesPss_ThenGetHashAlgorithmReturnPkcs1(
            [Values(
                CoseSignatureAlgorithm.PS256,
                CoseSignatureAlgorithm.PS384,
                CoseSignatureAlgorithm.PS512)] CoseSignatureAlgorithm alg)
        {
            AssertThat.AreEqual(RSASignaturePadding.Pss, alg.GetRSASignaturePadding());
        }

        [Test]
        public void WhenSignatureAlgorithmNotRsa_ThenGetHashAlgorithmThrowsException()
        {
            AssertThat.Throws<ArgumentException>(
                () => CoseSignatureAlgorithm.ES256.GetRSASignaturePadding());
        }

        //---------------------------------------------------------------------
        // VerifySignature.
        //---------------------------------------------------------------------

#if NET6_0_OR_GREATER
        [Test]
        public void WhenCertificateUsesRsa_ThenVerifySignatureSucceeds(
            [Values(
                CoseSignatureAlgorithm.RS256,
                CoseSignatureAlgorithm.RS384,
                CoseSignatureAlgorithm.RS512,
                CoseSignatureAlgorithm.PS256,
                CoseSignatureAlgorithm.PS384)] CoseSignatureAlgorithm alg)
        {
            using (var key = RSACng.Create())
            {
                var hashAlg = alg.GetHashAlgorithm().GetName();
                var request = new CertificateRequest(
                    "CN=Test",
                    key,
                    hashAlg,
                    alg.GetRSASignaturePadding());
                var certificate = request.CreateSelfSigned(
                    DateTimeOffset.UtcNow.AddHours(-1),
                    DateTimeOffset.UtcNow.AddHours(1));

                var data = Encoding.ASCII.GetBytes("some data");
                var signature = key.SignData(data, hashAlg, alg.GetRSASignaturePadding());

                AssertThat.IsTrue(alg.VerifySignature(
                    data,
                    signature,
                    certificate));
            }
        }

        [Test]
        public void WhenCertificateUsesEcdsa_ThenVerifySignatureSucceeds(
            [Values(
                CoseSignatureAlgorithm.ES256,
                CoseSignatureAlgorithm.ES384,
                CoseSignatureAlgorithm.ES512)] CoseSignatureAlgorithm alg)
        {
            using (var key = ECDsaCng.Create())
            {
                var hashAlg = alg.GetHashAlgorithm().GetName();
                var request = new CertificateRequest(
                    "CN=Test",
                    key,
                    hashAlg);
                var certificate = request.CreateSelfSigned(
                    DateTimeOffset.UtcNow.AddHours(-1),
                    DateTimeOffset.UtcNow.AddHours(1));

                var data = Encoding.ASCII.GetBytes("some data");
                var signature = key.SignData(data, hashAlg, DSASignatureFormat.Rfc3279DerSequence);

                AssertThat.IsTrue(alg.VerifySignature(
                    data,
                    signature,
                    certificate));
            }
        }
#endif
    }
}
