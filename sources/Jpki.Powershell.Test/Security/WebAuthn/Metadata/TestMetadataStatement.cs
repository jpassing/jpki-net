//
// Copyright 2024 Johannes Passing
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

using Jpki.Powershell.Runtime.Text;
using Jpki.Security.WebAuthn.Metadata;
using NUnit.Framework;
using System;
using System.Linq;

namespace Jpki.Powershell.Test.Security.WebAuthn.Metadata
{
    [TestFixture]
    public class TestMetadataStatement
    {
        [Test]
        public void YubiKey5ci()
        {
            var statement = Json.Deserialize<MetadataStatement>(
                MdsSampleData.MetadataStatements.YubiKey5ci)!;

            AssertThat.NotNull(statement);
            AssertThat.AreEqual("...", statement.LegalHeader);
            AssertThat.AreEqual("YubiKey 5 Series with Lightning", statement.Description);
            CollectionAssertThat.AreEquivalent(
                new[] { "secp256r1_ecdsa_sha256_raw" }, 
                statement.AuthenticationAlgorithms!);
            CollectionAssertThat.AreEquivalent(
                new[] { "hardware", "secure_element", "remote_handle" },
                statement.KeyProtection!);
            AssertThat.AreEqual("u2f", statement.ProtocolFamily);
            AssertThat.AreEqual(1, statement!.Upv![0].Major);
            AssertThat.AreEqual(1, statement!.Upv![0].Minor);
            CollectionAssertThat.AreEquivalent(
                new[] { new[] { new MetadataStatement.UserVerificationDescriptor("presence_internal") } },
                statement.UserVerificationDetails!);

            AssertThat.IsNull(statement.AuthenticatorGetInfo);
        }

        [Test]
        public void YubiKey5Nfc()
        {
            var statement = Json.Deserialize<MetadataStatement>(
                MdsSampleData.MetadataStatements.YubiKey5Nfc)!;

            AssertThat.NotNull(statement);
            AssertThat.AreEqual("...", statement.LegalHeader);
            AssertThat.AreEqual(Guid.Parse("fa2b99dc-9e39-4257-8f92-4a30d23c4118"), statement.Aaguid);
            AssertThat.AreEqual("YubiKey 5 Series with NFC", statement.Description);
            CollectionAssertThat.AreEquivalent(
                new[] { "ed25519_eddsa_sha512_raw", "secp256r1_ecdsa_sha256_raw" },
                statement.AuthenticationAlgorithms!);
            CollectionAssertThat.AreEquivalent(
                new[] { "hardware", "secure_element" },
                statement.KeyProtection!);
            AssertThat.AreEqual("fido2", statement.ProtocolFamily);
            AssertThat.AreEqual(1, statement!.Upv![0].Major);
            AssertThat.AreEqual(0, statement!.Upv![0].Minor);

            AssertThat.AreEqual(
                new MetadataStatement.UserVerificationDescriptor("passcode_external"),
                statement.UserVerificationDetails![0][0]);
            AssertThat.AreEqual(
                new MetadataStatement.UserVerificationDescriptor("none"),
                statement.UserVerificationDetails![1][0]);
            AssertThat.AreEqual(
                new MetadataStatement.UserVerificationDescriptor("passcode_external"),
                statement.UserVerificationDetails![2][0]);
            AssertThat.AreEqual(
                new MetadataStatement.UserVerificationDescriptor("presence_internal"),
                statement.UserVerificationDetails![2][1]);
            AssertThat.AreEqual(
                new MetadataStatement.UserVerificationDescriptor("presence_internal"),
                statement.UserVerificationDetails![3][0]);

            AssertThat.IsNotNull(statement.UserVerificationDetails![0]![0]!.CodeAccuracy);
            AssertThat.AreEqual(64, statement.UserVerificationDetails![0]![0]!.CodeAccuracy!.Base);

            AssertThat.IsNotNull(statement.AuthenticatorGetInfo);
            var authenticatorGetInfo = statement.AuthenticatorGetInfo!;
            AssertThat.AreEqual(statement.Aaguid, authenticatorGetInfo!.Aaguid);
            CollectionAssertThat.AreEquivalent(
                new[] { "hmac-secret" },
                authenticatorGetInfo.Extensions!);
            AssertThat.AreEqual(1200, authenticatorGetInfo.MaxMsgSize);
            AssertThat.AreEqual(false, authenticatorGetInfo.Options!["plat"]);
            AssertThat.AreEqual(true, authenticatorGetInfo.Options["rk"]);
            AssertThat.AreEqual(true, authenticatorGetInfo.Options["clientPin"]);
            AssertThat.AreEqual(true, authenticatorGetInfo.Options["up"]);
            CollectionAssertThat.AreEquivalent(
                new[] { 1 },
                authenticatorGetInfo.PinUvAuthProtocols!);

        }
    }
}
