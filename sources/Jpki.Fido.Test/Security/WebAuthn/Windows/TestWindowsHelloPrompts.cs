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

using Jpki.Security.WebAuthn;
using Jpki.Security.WebAuthn.Windows;
using NUnit.Framework;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Jpki.Test.Security.WebAuthn.Windows
{
    [TestFixture]
    [RequiresHumanInteraction]
    [Apartment(ApartmentState.STA)]
    public class TestWindowsHelloPrompts
    {
        private Form? form;

        [SetUp]
        public void CreateWindwow()
        {
            this.form = new Form()
            {
                Text = "Testing WebAuthN"
            };
            this.form.Show();
        }

        [TearDown]
        public void DestroyWindow()
        {
            this.form?.Close();
        }

        [Test]
        public async Task NonResidentKeyWithoutAttestationAndUserVerification()
        {
            var credential = await WindowsHello
                .CreateCredentialAsync(
                    this.form!.Handle,
                    Data.NonResidentRelyingParty,
                    Data.User,
                    ClientData.FromJson("{}"),
                    new WindowsHello.AttestationOptions()
                    {
                        Attestation = AttestationConveyance.None,
                        ResidentKey = ResidentKeyRequirement.Any,
                        UserVerification = UserVerificationRequirement.Discouraged
                    },
                    CancellationToken.None)
                .ConfigureAwait(true);

            Assert.IsNotNull(credential);
            Assert.IsNull(credential.AttestationStatement);
            Assert.IsTrue(credential.AuthenticatorData.Flags.HasFlag(AuthenticatorDataFlags.UserPresent));

            var assertion = await WindowsHello
                .CreateAssertionAsync(
                    this.form.Handle,
                    Data.NonResidentRelyingParty,
                    ClientData.FromJson("{}"),
                    new WindowsHello.AssertionOptions()
                    {
                        AllowedCredentials = new[] { credential.Id },
                        UserVerification = UserVerificationRequirement.Discouraged
                    },
                    CancellationToken.None)
                .ConfigureAwait(true);

            Assert.IsNull(assertion.UserId);
            Assert.IsTrue(assertion.AuthenticatorData.Flags.HasFlag(AuthenticatorDataFlags.UserPresent));
            Assert.IsFalse(assertion.AuthenticatorData.Flags.HasFlag(AuthenticatorDataFlags.UserVerified));

            assertion.Verify(credential);
        }

        [Test]
        public async Task NonResidentKeyWithAttestationAndUserVerification()
        {
            var credential = await WindowsHello
                .CreateCredentialAsync(
                    this.form!.Handle,
                    Data.NonResidentRelyingParty,
                    Data.User,
                    ClientData.FromJson("{}"),
                    new WindowsHello.AttestationOptions()
                    {
                        Attestation = AttestationConveyance.Indirect,
                        UserVerification = UserVerificationRequirement.Required
                    },
                    CancellationToken.None)
                .ConfigureAwait(true);

            Assert.IsNotNull(credential);
            credential.Verify();

            Assert.IsNotNull(credential.AttestationStatement);
            Assert.IsNotNull(credential.AttestationStatement!.CertificateChain);
            CollectionAssert.IsNotEmpty(credential.AttestationStatement.CertificateChain);

            Assert.IsTrue(credential.AuthenticatorData.Flags.HasFlag(AuthenticatorDataFlags.UserPresent));
            Assert.IsTrue(credential.AuthenticatorData.Flags.HasFlag(AuthenticatorDataFlags.UserVerified));

            var assertion = await WindowsHello
                .CreateAssertionAsync(
                    this.form.Handle,
                    Data.NonResidentRelyingParty,
                    ClientData.FromJson("{}"),
                    new WindowsHello.AssertionOptions()
                    {
                        AllowedCredentials = new[] { credential.Id },
                        UserVerification = UserVerificationRequirement.Required
                    },
                    CancellationToken.None)
                .ConfigureAwait(true);

            Assert.IsNull(assertion.UserId);
            Assert.IsTrue(assertion.AuthenticatorData.Flags.HasFlag(AuthenticatorDataFlags.UserPresent));
            Assert.IsTrue(assertion.AuthenticatorData.Flags.HasFlag(AuthenticatorDataFlags.UserVerified));

            assertion.Verify(credential);
        }

        [Test]
        public async Task ResidentKey()
        {
            var credential = await WindowsHello
                .CreateCredentialAsync(
                    this.form!.Handle,
                    Data.ResidentRelyingParty,
                    Data.User,
                    ClientData.FromJson("{}"),
                    new WindowsHello.AttestationOptions()
                    {
                        ResidentKey = ResidentKeyRequirement.Required
                    },
                    CancellationToken.None)
                .ConfigureAwait(true);

            Assert.IsNotNull(credential);

            var assertion = await WindowsHello
                .CreateAssertionAsync(
                    this.form.Handle,
                    Data.ResidentRelyingParty,
                    ClientData.FromJson("{}"),
                    new WindowsHello.AssertionOptions()
                    {
                        AllowedCredentials = new[] { credential.Id }
                    },
                    CancellationToken.None)
                .ConfigureAwait(true);

            Assert.AreEqual(Data.User.Id, assertion.UserId);
            assertion.Verify(credential);
        }
    }
}
