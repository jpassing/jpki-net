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
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Jpki.Test.Security.WebAuthn.Windows
{
    [TestFixture]
    [Apartment(ApartmentState.STA)]
    public class TestWindowsHello
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
            this.form.Disposed += (s, e) => { };
        }

        [TearDown]
        public async Task DestroyWindow()
        {
            await Task.Delay(150);
            this.form?.Close();
        }

        //---------------------------------------------------------------------
        // ApiVersionNumber.
        //---------------------------------------------------------------------

        [Test]
        public void ApiVersionNumber()
        {
            AssertThat.AreNotEqual(0, WindowsHello.ApiVersion);
        }

        //---------------------------------------------------------------------
        // CreateCredential.
        //---------------------------------------------------------------------

        [Test]
        public void ApiVersion()
        {
            AssertThat.GreaterOrEqual(WindowsHello.ApiVersion, 2);
        }

        //---------------------------------------------------------------------
        // CreateCredential.
        //---------------------------------------------------------------------

        [Test]
        public void WhenSignatureAlgorithmsEmpty_ThenCreateCredentialThrowsException()
        {
            AssertThrows.AggregateException<ArgumentException>(
                () => Authenticators.WindowsHello
                    .CreateCredentialAsync(
                        this.form!.Handle,
                        Data.NonResidentRelyingParty,
                        Data.User,
                        ClientData.FromJson("{}"),
                        new AttestationOptions()
                        {
                            SignatureAlgorithms = Array.Empty<CoseSignatureAlgorithm>()
                        },
                        CancellationToken.None)
                    .Wait());
        }

        [Test]
        public void WhenSignatureAlgorithmsInvalid_ThenCreateCredentialThrowsException()
        {
            AssertThrows.AggregateException<ArgumentException>(
                () => Authenticators.WindowsHello
                    .CreateCredentialAsync(
                        this.form!.Handle,
                        Data.NonResidentRelyingParty,
                        Data.User,
                        ClientData.FromJson("{}"),
                        new AttestationOptions()
                        {
                            SignatureAlgorithms = new[] { (CoseSignatureAlgorithm)9999 }
                        },
                        CancellationToken.None)
                    .Wait());
        }

        [Test]
        [RequiresHumanInteraction]
        public void WhenNoPlatformAuthenticatorPresent_ThenCreateCredentialThrowsException()
        {
            if (Authenticators.IsPlatformAuthenticatorAvailable)
            {
                AssertThat.Inconclusive("Platform authenticator present");
                return;
            }

            AssertThrows.AggregateException<WebAuthnException>(
                () => Authenticators.WindowsHello
                    .CreateCredentialAsync(
                        this.form!.Handle,
                        Data.NonResidentRelyingParty,
                        Data.User,
                        ClientData.FromJson("{}"),
                        new AttestationOptions()
                        {
                            AuthenticatorAttachment = AuthenticatorAttachment.Platform
                        },
                        CancellationToken.None)
                    .Wait());
        }

        [Test]
        [RequiresHumanInteraction]
        public async Task WhenCancelled_ThenCreateCredentialThrowsException()
        {
            using (var cts = new CancellationTokenSource())
            {
                var attestationTask = Authenticators.WindowsHello
                    .CreateCredentialAsync(
                        this.form!.Handle,
                        Data.NonResidentRelyingParty,
                        Data.User,
                        ClientData.FromJson("{}"),
                        new AttestationOptions(),
                        cts.Token);

                await Task.Delay(250);
                cts.Cancel();

                AssertThrows.AggregateException<OperationCanceledException>(
                    () => attestationTask.Wait());
            }
        }

        //---------------------------------------------------------------------
        // CreateAssertion.
        //---------------------------------------------------------------------

        [Test]
        [RequiresHumanInteraction]
        public async Task WhenCancelled_ThenCreateAssertionThrowsException()
        {
            using (var cts = new CancellationTokenSource())
            {
                var attestationTask = Authenticators.WindowsHello
                    .CreateAssertionAsync(
                        this.form!.Handle,
                        Data.NonResidentRelyingParty,
                        ClientData.FromJson("{}"),
                        new AssertionOptions(),
                        cts.Token);

                await Task.Delay(250);
                cts.Cancel();

                AssertThrows.AggregateException<OperationCanceledException>(
                    () => attestationTask.Wait());
            }
        }

        [Test]
        [RequiresHumanInteraction]
        public async Task CreateAssertionWithoutAttestationAndUserVerification()
        {
            var credential = await Authenticators.WindowsHello
                .CreateCredentialAsync(
                    this.form!.Handle,
                    Data.NonResidentRelyingParty,
                    Data.User,
                    ClientData.FromJson("{}"),
                    new AttestationOptions()
                    {
                        Attestation = AttestationConveyance.None,
                        ResidentKey = ResidentKeyRequirement.Any,
                        UserVerification = UserVerificationRequirement.Discouraged
                    },
                    CancellationToken.None)
                .ConfigureAwait(true);

            AssertThat.IsNotNull(credential);
            AssertThat.IsNull(credential.AttestationStatement);
            AssertThat.IsTrue(credential.AuthenticatorData.Flags.HasFlag(AuthenticatorDataFlags.UserPresent));

            var assertion = await Authenticators.WindowsHello
                .CreateAssertionAsync(
                    this.form.Handle,
                    Data.NonResidentRelyingParty,
                    ClientData.FromJson("{}"),
                    new AssertionOptions()
                    {
                        AllowedCredentials = new[] { credential.Id },
                        UserVerification = UserVerificationRequirement.Discouraged
                    },
                    CancellationToken.None)
                .ConfigureAwait(true);

            AssertThat.IsNull(assertion.UserId);
            AssertThat.IsTrue(assertion.AuthenticatorData.Flags.HasFlag(AuthenticatorDataFlags.UserPresent));
            AssertThat.IsFalse(assertion.AuthenticatorData.Flags.HasFlag(AuthenticatorDataFlags.UserVerified));

            assertion.Verify(credential);
        }

        [Test]
        [RequiresHumanInteraction]
        public async Task CreateAssertioWithAttestationAndUserVerification()
        {
            var credential = await Authenticators.WindowsHello
                .CreateCredentialAsync(
                    this.form!.Handle,
                    Data.NonResidentRelyingParty,
                    Data.User,
                    ClientData.FromJson("{}"),
                    new AttestationOptions()
                    {
                        Attestation = AttestationConveyance.Indirect,
                        UserVerification = UserVerificationRequirement.Required
                    },
                    CancellationToken.None)
                .ConfigureAwait(true);

            AssertThat.IsNotNull(credential);
            credential.Verify();

            AssertThat.IsNotNull(credential.AttestationStatement);
            AssertThat.IsNotNull(credential.AttestationStatement!.CertificateChain);
            CollectionAssertThat.IsNotEmpty(credential.AttestationStatement.CertificateChain!);

            AssertThat.IsTrue(credential.AuthenticatorData.Flags.HasFlag(AuthenticatorDataFlags.UserPresent));
            AssertThat.IsTrue(credential.AuthenticatorData.Flags.HasFlag(AuthenticatorDataFlags.UserVerified));

            var assertion = await Authenticators.WindowsHello
                .CreateAssertionAsync(
                    this.form.Handle,
                    Data.NonResidentRelyingParty,
                    ClientData.FromJson("{}"),
                    new AssertionOptions()
                    {
                        AllowedCredentials = new[] { credential.Id },
                        UserVerification = UserVerificationRequirement.Required
                    },
                    CancellationToken.None)
                .ConfigureAwait(true);

            AssertThat.IsNull(assertion.UserId);
            AssertThat.IsTrue(assertion.AuthenticatorData.Flags.HasFlag(AuthenticatorDataFlags.UserPresent));
            AssertThat.IsTrue(assertion.AuthenticatorData.Flags.HasFlag(AuthenticatorDataFlags.UserVerified));

            assertion.Verify(credential);
        }

        [Test]
        [RequiresHumanInteraction]
        public async Task CreateAssertioWithResidentKey()
        {
            var credential = await Authenticators.WindowsHello
                .CreateCredentialAsync(
                    this.form!.Handle,
                    Data.ResidentRelyingParty,
                    Data.User,
                    ClientData.FromJson("{}"),
                    new AttestationOptions()
                    {
                        ResidentKey = ResidentKeyRequirement.Required
                    },
                    CancellationToken.None)
                .ConfigureAwait(true);

            AssertThat.IsNotNull(credential);

            var assertion = await Authenticators.WindowsHello
                .CreateAssertionAsync(
                    this.form.Handle,
                    Data.ResidentRelyingParty,
                    ClientData.FromJson("{}"),
                    new AssertionOptions()
                    {
                        AllowedCredentials = new[] { credential.Id }
                    },
                    CancellationToken.None)
                .ConfigureAwait(true);

            AssertThat.AreEqual(Data.User.Id, assertion.UserId);
            assertion.Verify(credential);
        }
    }
}
#endif