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
using Jpki.Security.WebAuthn;
using NUnit.Framework;
using System;

namespace Jpki.Test.Security.WebAuthn
{
    [TestFixture]
    public class TestAuthenticatorData
    {
        private static readonly byte[] AuthenticatorData = Convert.FromBase64String(
            "NzBwf9oCdphG17wO4hMSr2PapN61uq3poxktEToxj/5BAAAAAAAAAAAAAAAAAAAA" +
            "AAAAAAAAQIApcyWMfKhA+2LUEeh6kGFqYpDXsaC5x8plCsRGKRRlsqwRJ2WSzaj7" +
            "8Vs19DJogVoCG5B+siLIl6zIWVmNvtClAQIDJiABIVggpP7p3hRL2Rd1B8ayF1tZ" +
            "+AWAAndrwWJeBV1Lp8bMZTQiWCBfcvUaPhjtXb8W4HDZcO706aa0lvY25LHWFg/S" +
            "TL2vqg==");

        private static readonly byte[] AuthenticatorDataWithoutCredentialData =
            Convert.FromBase64String(
                "NzBwf9oCdphG17wO4hMSr2PapN61uq3poxktEToxj/4BAAAAwA==");

        [Test]
        public void WhenDatLacksAttestedCredentialData_ThenCtorSucceeds()
        {
            var authData = new AuthenticatorData(AuthenticatorDataWithoutCredentialData);

            AssertThat.AreEqual(
                AuthenticatorDataFlags.UserPresent,
                authData.Flags);
            AssertThat.IsNull(authData.AttestedCredentialData);
        }

        [Test]
        public void WhenDataContainsAttestedCredentialData_ThenCtorSucceeds()
        {
            var authData = new AuthenticatorData(AuthenticatorData);

            AssertThat.AreEqual(
                AuthenticatorDataFlags.UserPresent | AuthenticatorDataFlags.AttestedCredentialDataIncluded,
                authData.Flags);
            AssertThat.AreEqual(0, authData.SignCount);
            AssertThat.AreEqual(32, authData.RelyingPartyIdHash.Length);
            AssertThat.AreEqual(55, authData.RelyingPartyIdHash[0]);
            AssertThat.AreEqual(64, authData.AttestedCredentialData!.CredentialId.Value.Length);
            AssertThat.AreEqual(128, authData.AttestedCredentialData.CredentialId.Value[0]);
            AssertThat.AreEqual(Guid.Empty, authData.AttestedCredentialData.Aaguid);

            AssertThat.IsNotNull(authData.AttestedCredentialData.Key);
            AssertThat.AreEqual(CoseKeyType.EC2, authData.AttestedCredentialData.Key.KeyType);
            AssertThat.AreEqual(CoseSignatureAlgorithm.ES256, authData.AttestedCredentialData.Key.Algorithm);
        }

        [Test]
        public void WhenDataTruncated_ThenCtorThrowsException()
        {
            AssertThat.Throws<ArgumentException>(
                () => new AuthenticatorData(new byte[36]));
        }
    }
}
