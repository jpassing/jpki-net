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

#if WINDOWS || NETFRAMEWORK

using Jpki.Security.Cryptography.Cose;
using Jpki.Security.WebAuthn;
using Jpki.Security.WebAuthn.Windows;
using NUnit.Framework;
using System;
using System.Collections.Generic;

namespace Jpki.Test.Security.WebAuthn.Windows
{
    [TestFixture]
    public class TestNativeConvert
    {
        //---------------------------------------------------------------------
        // ClientData.
        //---------------------------------------------------------------------

        [Test]
        public void ClientDataJson(
            [Values(
                CoseHashAlgorithm.SHA_256,
                CoseHashAlgorithm.SHA_384,
                CoseHashAlgorithm.SHA_512)] CoseHashAlgorithm hashAlgorithm)
        {
            var clientData = ClientData.FromJson("{'test': 1}", hashAlgorithm);

            using (clientData.ToNative(out var native))
            {
                AssertThat.AreEqual(NativeMethods.WEBAUTHN_CLIENT_DATA.BaselineVersion, native.dwVersion);
                AssertThat.AreEqual(clientData.Data.Length, native.cbClientDataJSON);
                AssertThat.AreNotEqual(IntPtr.Zero, native.pbClientDataJSON);
                StringAssertThat.StartsWith("SHA-", native.pwszHashAlgId);
            }
        }

        //---------------------------------------------------------------------
        // User.
        //---------------------------------------------------------------------

        [Test]
        public void UserWithAllProperties()
        {
            var user = new User(
                new byte[] { 1, 2, 3 },
                "user",
                "Display",
                new Uri("Https://example.com/icon.ico"));

            using (user.ToNative(out var native))
            {
                AssertThat.AreEqual(NativeMethods.WEBAUTHN_USER_ENTITY_INFORMATION.BaselineVersion, native.dwVersion);
                AssertThat.AreEqual(3, native.cbId);
                AssertThat.AreNotEqual(IntPtr.Zero, native.pbId);
                AssertThat.IsNotNull(native.pwszName);
                AssertThat.IsNotNull(native.pwszIcon);
                AssertThat.IsNotNull(native.pwszDisplayName);
            }
        }

        [Test]
        public void UserWithMinimalProperties()
        {
            var user = new User(new byte[] { 1, 2, 3 }, null, null, null);

            using (user.ToNative(out var native))
            {
                AssertThat.AreEqual(NativeMethods.WEBAUTHN_USER_ENTITY_INFORMATION.BaselineVersion, native.dwVersion);
                AssertThat.AreEqual(3, native.cbId);
                AssertThat.AreNotEqual(IntPtr.Zero, native.pbId);
                AssertThat.IsNull(native.pwszName);
                AssertThat.IsNull(native.pwszIcon);
                AssertThat.IsNull(native.pwszDisplayName);
            }
        }

        //---------------------------------------------------------------------
        // CredentialId.
        //---------------------------------------------------------------------

        [Test]
        public void CredentialId()
        {
            var credential = new CredentialId(new byte[] { 0xAA, 0xBB, 0xCC, 0xDD });

            using (credential.ToNative(Transport.Any, out var native))
            {
                var recovered = NativeConvert.FromNative(native);
                AssertThat.AreEqual(credential, recovered);
            }
        }

        //---------------------------------------------------------------------
        // CredentialList.
        //---------------------------------------------------------------------

        [Test]
        public void NullCredentialList()
        {
            ICollection<CredentialId> credentialList = null;

            using (credentialList.ToNative(Transport.Any, out var native))
            {
                AssertThat.IsNull(native);
            }
        }

        [Test]
        public void EmptyCredentialList()
        {
            var credentialList = Array.Empty<CredentialId>();

            using (credentialList.ToNative(Transport.Any, out var native))
            {
                var recovered = NativeConvert.FromNative(native);
                CollectionAssertThat.AreEquivalent(credentialList, recovered!);
            }
        }

        [Test]
        public void CredentialList()
        {
            var credentialList = new[] {
                new CredentialId(new byte[] { 0xAA, 0xBB, 0xCC }),
                new CredentialId(new byte[] { 0xAA, 0xBB, 0xCC, 0xDD })
            };

            using (credentialList.ToNative(Transport.Any, out var native))
            {
                var recovered = NativeConvert.FromNative(native);
                CollectionAssertThat.AreEquivalent(credentialList, recovered!);
            }
        }
    }
}
#endif