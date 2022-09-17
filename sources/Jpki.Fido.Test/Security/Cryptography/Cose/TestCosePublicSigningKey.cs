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

using Jpki.Format.Cbor;
using Jpki.Security.Cryptography.Cose;
using NUnit.Framework;
using System;

namespace Jpki.Test.Security.Cryptography.Cose
{
    [TestFixture]
    public class TestCosePublicSigningKey
    {
        private static readonly byte[] EcdsaKey = Convert.FromBase64String(
            "pQECAyYgASFYIKT+6d4US9kXdQfGshdbWfgFgAJ3a8FiXgVdS6fGzGU0IlggX3L1G" +
            "j4Y7V2/FuBw2XDu9OmmtJb2NuSx1hYP0ky9r6o=");

        private static readonly byte[] RsaKey = Convert.FromBase64String(
            "qgEDAzkBACFDAQABIFhAzgOMq745BthWHvO84og5DP/GQqukMCGjx6jV/MRyKzAqK" +
            "5NZq2wFAjoAUOFzz+lAV5CkNUk2qD4br0ALzP9p8SJYQBf1pbibqPo40ttKsZ8PBM" +
            "OUQ7ShTbkjUG76HdkF59lJzRtTDJVY6Nq2Ceh9VQ6R2oCcDsocEbwIjcQShhq/YNk" +
            "jWCD7R78VkPAiiFjAm9caBNdHiL91pHEdbvOCk6SZ8JFvJyRYINHiJQMiBkGbb9ah" +
            "HYK0moAl2xOfl/PfIl4bqiZhyY0nJVggkQIqZ4uoyITekuhcDYvVoFZuBrnK/S1WI" +
            "XiKeLu3cekmWCB9HoCMDpOGNwCEBcZO7hWQwYCJgUGXu3SEf59+hBsgTydYIOntWy" +
            "NNfNyXGoBW3sCryR2XZtZnLsLIBFad0uGMiCHd");

        [Test]
        public void Ecdsa()
        {
            using (var key = CosePublicKey.Decode(new CborData(EcdsaKey)))
            {
                Assert.AreEqual(CoseKeyType.EC2, key.KeyType);
                Assert.AreEqual(CoseSignatureAlgorithm.ES256, key.Algorithm);

                Assert.IsInstanceOf<CoseEcdsaPublicKey>(key);
                Assert.IsNotNull(((CoseEcdsaPublicKey)key).Key);
            }
        }

        [Test]
        public void Rsa()
        {
            using (var key = CosePublicKey.Decode(new CborData(RsaKey)))
            {
                Assert.AreEqual(CoseKeyType.RSA, key.KeyType);
                Assert.AreEqual(CoseSignatureAlgorithm.RS256, key.Algorithm);

                Assert.IsInstanceOf<CoseRsaPublicKey>(key);
                Assert.IsNotNull(((CoseRsaPublicKey)key).Key);
            }
        }
    }
}
