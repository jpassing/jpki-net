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
        // CreateCredential.
        //---------------------------------------------------------------------

        [Test]
        public void WhenSignatureAlgorithmsEmpty_ThenCreateCredentialThrowsException()
        {
            ExceptionAssert.ThrowsAggregateException<ArgumentException>(
                () => WindowsHello
                    .CreateCredentialAsync(
                        this.form!.Handle,
                        Data.NonResidentRelyingParty,
                        Data.User,
                        ClientData.FromJson("{}"),
                        new WindowsHello.AttestationOptions()
                        {
                            SignatureAlgorithms = Array.Empty<CoseSignatureAlgorithm>()
                        },
                        CancellationToken.None)
                    .Wait());
        }

        [Test]
        public void WhenSignatureAlgorithmsInvalid_ThenCreateCredentialThrowsException()
        {
            ExceptionAssert.ThrowsAggregateException<ArgumentException>(
                () => WindowsHello
                    .CreateCredentialAsync(
                        this.form!.Handle,
                        Data.NonResidentRelyingParty,
                        Data.User,
                        ClientData.FromJson("{}"),
                        new WindowsHello.AttestationOptions()
                        {
                            SignatureAlgorithms = new[] { (CoseSignatureAlgorithm)9999 }
                        },
                        CancellationToken.None)
                    .Wait());
        }

        [Test]
        public void WhenNoPlatformAuthenticatorPresent_ThenCreateCredentialThrowsException()
        {
            if (WindowsHello.IsPlatformAuthenticatorAvailable)
            {
                Assert.Inconclusive("Platform authenticator present");
                return;
            }

            ExceptionAssert.ThrowsAggregateException<WebAuthnException>(
                () => WindowsHello
                    .CreateCredentialAsync(
                        this.form!.Handle,
                        Data.NonResidentRelyingParty,
                        Data.User,
                        ClientData.FromJson("{}"),
                        new WindowsHello.AttestationOptions()
                        {
                            Authenticator = AuthenticatorAttachment.Platform
                        },
                        CancellationToken.None)
                    .Wait());
        }

        [Test]
        public async Task WhenCancelled_ThenCreateCredentialThrowsException()
        {
            using (var cts = new CancellationTokenSource())
            {
                var attestationTask = WindowsHello
                    .CreateCredentialAsync(
                        this.form!.Handle,
                        Data.NonResidentRelyingParty,
                        Data.User,
                        ClientData.FromJson("{}"),
                        new WindowsHello.AttestationOptions(),
                        cts.Token);

                await Task.Delay(250);
                cts.Cancel();

                ExceptionAssert.ThrowsAggregateException<OperationCanceledException>(
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
                var attestationTask = WindowsHello
                    .CreateAssertionAsync(
                        this.form!.Handle,
                        Data.NonResidentRelyingParty,
                        ClientData.FromJson("{}"),
                        new WindowsHello.AssertionOptions(),
                        cts.Token);

                await Task.Delay(250);
                cts.Cancel();

                ExceptionAssert.ThrowsAggregateException<OperationCanceledException>(
                    () => attestationTask.Wait());
            }
        }
    }
}
