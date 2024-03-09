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
using Jpki.Security.WebAuthn;
using NUnit.Framework;
using System;

namespace Jpki.Test.Security.WebAuthn
{
    [TestFixture]
    public class TestCredential
    {
        //
        // NB. Assertions have been created using the Chrome simulator.
        //

        [Test]
        public void Ctap2CredentialWithoutAttestation()
        {
            var clientData = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlb" +
                "mdlIjoiIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwiY3J" +
                "vc3NPcmlnaW4iOmZhbHNlfQ==  ";
            var attestationObject = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YV" +
                "ikSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NBAAAAAQAAAAAA" +
                "AAAAAAAAAAAAAAAAILU9T36NIyNCb9v1nnq5bCrlIxoCSLUSCzbjQAFiy5" +
                "H2pQECAyYgASFYILsJWzm3jYWhKtYCYtKeeP7/kcFiF06cMFbItFjdg56O" +
                "Ilgg30wpXe8vwtlYCLyp9c//+eJ41EpQzN66FBSSaAy3+TQ=";
            var credentialId = "tT1Pfo0jI0Jv2/WeerlsKuUjGgJItRILNuNAAWLLkfY=";

            var credential = Credential.Decode(
                new CborData(Convert.FromBase64String(attestationObject)),
                new ClientData(Convert.FromBase64String(clientData), CoseHashAlgorithm.SHA_256),
                new CredentialId(Convert.FromBase64String(credentialId)),
                Transport.Test);

            AssertThat.IsFalse(credential.IsFidoU2F);

            AssertThat.IsNull(credential.AttestationStatement);
            AssertThat.IsTrue(credential.AuthenticatorData.Flags.HasFlag(AuthenticatorDataFlags.UserPresent));
            AssertThat.IsTrue(credential.AuthenticatorData.Flags.HasFlag(AuthenticatorDataFlags.AttestedCredentialDataIncluded));

            AssertThat.IsNotNull(credential.AuthenticatorData.AttestedCredentialData);
            AssertThat.AreEqual(
                credential.Id,
                credential.AuthenticatorData.AttestedCredentialData!.CredentialId);
            AssertThat.AreEqual(
                Guid.Empty,
                credential.AuthenticatorData.AttestedCredentialData.Aaguid);

            AssertThat.Throws<WebAuthnException>(() => credential.Verify());
        }

        [Test]
        public void Ctap2CredentialWithAssertionAndUserVerification()
        {
            var clientData = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlb" +
                "mdlIjoiY21GdVpHOXRJR05vWVd4c1pXNW5aUSIsIm9yaWdpbiI6Imh0dHA" +
                "6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZ" +
                "XJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGN" +
                "saWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzO" +
                "i8vZ29vLmdsL3lhYlBleCJ9";
            var attestationObject = "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2" +
                "lnWEcwRQIgN1xtH9bVxJBQURqT4oo/di7wyoujg4VC387L5aopLIECIQC3" +
                "WdNiu9TqvKWlIbWfsPqrdLTE88nm6vnbmdYrCU1a8mN4NWOBWQHeMIIB2j" +
                "CCAX2gAwIBAgIBATANBgkqhkiG9w0BAQsFADBgMQswCQYDVQQGEwJVUzER" +
                "MA8GA1UECgwIQ2hyb21pdW0xIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQX" +
                "R0ZXN0YXRpb24xGjAYBgNVBAMMEUJhdGNoIENlcnRpZmljYXRlMB4XDTE3" +
                "MDcxNDAyNDAwMFoXDTQyMTAzMTAwMTI1M1owYDELMAkGA1UEBhMCVVMxET" +
                "APBgNVBAoMCENocm9taXVtMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0" +
                "dGVzdGF0aW9uMRowGAYDVQQDDBFCYXRjaCBDZXJ0aWZpY2F0ZTBZMBMGBy" +
                "qGSM49AgEGCCqGSM49AwEHA0IABI1hfmXJUI5kvMVnOsgqZ5naPBRGaCwl" +
                "jEY//99Y39L6Pmw3i1PXlcSk3/tBme3Xhi8jq68CA7S4kRugVpmU4QGjJT" +
                "AjMAwGA1UdEwEB/wQCMAAwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZI" +
                "hvcNAQELBQADSAAwRQIgYIUgBGBH2Xi5amUsX/UauHCigrTUzUk7/oAvEK" +
                "Yt89wCIQCoQQ4YFtXeReDP4WoJ9GE86EVXmwGYb4myi5r4IB8ZJ2hhdXRo" +
                "RGF0YVikSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NFAAAAAQ" +
                "ECAwQFBgcIAQIDBAUGBwgAIC7cT8ohwJ0Q2yFB7aeRdSHHRhdPkeT4ySgo" +
                "bH9A3ytUpQECAyYgASFYIFHFJy6vnPqi8GcEGBxIXZigGXuB6JtYQan98d" +
                "/mcSG1Ilgg1O/g8OZlowMvSLeLX1ZSnehUkJIDBI6xx98KP0glZM0=";
            var credentialId = "LtxPyiHAnRDbIUHtp5F1IcdGF0+R5PjJKChsf0DfK1Q=";

            var credential = Credential.Decode(
                new CborData(Convert.FromBase64String(attestationObject)),
                new ClientData(Convert.FromBase64String(clientData), CoseHashAlgorithm.SHA_256),
                new CredentialId(Convert.FromBase64String(credentialId)),
                Transport.Test);

            AssertThat.IsFalse(credential.IsFidoU2F);

            AssertThat.IsNotNull(credential.AttestationStatement);
            AssertThat.AreEqual(CoseSignatureAlgorithm.ES256, credential.AttestationStatement!.Algorithm);
            AssertThat.IsFalse(credential.AttestationStatement.IsSelfAttested);

            AssertThat.IsNotNull(credential.AttestationStatement.Certificate);
            AssertThat.AreEqual(
                "CN=Batch Certificate, OU=Authenticator Attestation, O=Chromium, C=US",
                credential.AttestationStatement.Certificate!.Subject);

            AssertThat.IsTrue(credential.AuthenticatorData.Flags.HasFlag(AuthenticatorDataFlags.UserPresent));
            AssertThat.IsTrue(credential.AuthenticatorData.Flags.HasFlag(AuthenticatorDataFlags.UserVerified));
            AssertThat.IsTrue(credential.AuthenticatorData.Flags.HasFlag(AuthenticatorDataFlags.AttestedCredentialDataIncluded));

            AssertThat.IsNotNull(credential.AuthenticatorData.AttestedCredentialData);
            AssertThat.AreEqual(
                credential.Id,
                credential.AuthenticatorData.AttestedCredentialData!.CredentialId);
            AssertThat.AreEqual(
                "04030201-0605-0807-0102-030405060708",
                credential.AuthenticatorData.AttestedCredentialData.Aaguid.ToString());

            credential.Verify();
        }


        [Test]
        public void Ctap2CredentialWithAssertion()
        {
            var clientData = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbm" +
                "dlIjoiY21GdVpHOXRJR05vWVd4c1pXNW5aUSIsIm9yaWdpbiI6Imh0dHA6L" +
                "y9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0=";
            var attestationObject = "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2l" +
                "nWEcwRQIgajrRnBdtpAf961Dm0lw/T+F3nn6glBjCdh6aGOogaX0CIQCGSB" +
                "kfPptqh79QNPXBqndMXKDYk8SHmt+BYhr4qVaiVGN4NWOBWQHfMIIB2zCCA" +
                "X2gAwIBAgIBATANBgkqhkiG9w0BAQsFADBgMQswCQYDVQQGEwJVUzERMA8G" +
                "A1UECgwIQ2hyb21pdW0xIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN" +
                "0YXRpb24xGjAYBgNVBAMMEUJhdGNoIENlcnRpZmljYXRlMB4XDTE3MDcxND" +
                "AyNDAwMFoXDTQyMTAzMTAwMjEwMlowYDELMAkGA1UEBhMCVVMxETAPBgNVB" +
                "AoMCENocm9taXVtMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0" +
                "aW9uMRowGAYDVQQDDBFCYXRjaCBDZXJ0aWZpY2F0ZTBZMBMGByqGSM49AgE" +
                "GCCqGSM49AwEHA0IABI1hfmXJUI5kvMVnOsgqZ5naPBRGaCwljEY//99Y39" +
                "L6Pmw3i1PXlcSk3/tBme3Xhi8jq68CA7S4kRugVpmU4QGjJTAjMAwGA1UdE" +
                "wEB/wQCMAAwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQAD" +
                "SQAwRgIhAOovxKVQ1UYlTM/0bHQi5+UTKsxwEFtggBRQIv/3JGykAiEAlhY" +
                "PPXCtgZ1djaQNr5vmJH7VJptRQO4yKyIrTK56VOloYXV0aERhdGFYpEmWDe" +
                "WIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAEBAgMEBQYHCAECA" +
                "wQFBgcIACA8UsCR3hmX4k2uY+VIqCa0jdc4N1jbXIkuH3k9c8OjXKUBAgMm" +
                "IAEhWCA+AwOo84iirzJkHkX5lekyrEo9ARxiIV1PT/yojf1wjSJYIPpJm4u" +
                "mhHou7UkMWCEr1ng4vNbY5fPA/8lyCeusvGRr";
            var credentialId = "PFLAkd4Zl+JNrmPlSKgmtI3XODdY21yJLh95PXPDo1w=";

            var credential = Credential.Decode(
                new CborData(Convert.FromBase64String(attestationObject)),
                new ClientData(Convert.FromBase64String(clientData), CoseHashAlgorithm.SHA_256),
                new CredentialId(Convert.FromBase64String(credentialId)),
                Transport.Test);

            AssertThat.IsFalse(credential.IsFidoU2F);

            AssertThat.IsNotNull(credential.AttestationStatement);
            AssertThat.AreEqual(CoseSignatureAlgorithm.ES256, credential.AttestationStatement!.Algorithm);
            AssertThat.IsFalse(credential.AttestationStatement.IsSelfAttested);


            AssertThat.IsNotNull(credential.AttestationStatement.Certificate);
            AssertThat.AreEqual(
                "CN=Batch Certificate, OU=Authenticator Attestation, O=Chromium, C=US",
                credential.AttestationStatement.Certificate!.Subject);

            AssertThat.IsTrue(credential.AuthenticatorData.Flags.HasFlag(AuthenticatorDataFlags.UserPresent));
            AssertThat.IsFalse(credential.AuthenticatorData.Flags.HasFlag(AuthenticatorDataFlags.UserVerified));
            AssertThat.IsTrue(credential.AuthenticatorData.Flags.HasFlag(AuthenticatorDataFlags.AttestedCredentialDataIncluded));

            AssertThat.IsNotNull(credential.AuthenticatorData.AttestedCredentialData);
            AssertThat.AreEqual(
                credential.Id,
                credential.AuthenticatorData.AttestedCredentialData!.CredentialId);
            AssertThat.AreEqual(
                "04030201-0605-0807-0102-030405060708",
                credential.AuthenticatorData.AttestedCredentialData.Aaguid.ToString());

            credential.Verify();
        }

        [Test]
        public void U2fCredential()
        {
            var clientData = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbm" +
                "dlIjoiY21GdVpHOXRJR05vWVd4c1pXNW5aUSIsIm9yaWdpbiI6Imh0dHA6L" +
                "y9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0=";
            var attestationObject = "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEc" +
                "wRQIhAPLmrpRNfGknYRPAi7uoSm1qzfOOt3H/FzqBOJL9pGKaAiBzRka7hT" +
                "4NsUl8eS8YjaKqz866mDlnhkreCi2DwUBY2mN4NWOBWQHdMIIB2TCCAX2gA" +
                "wIBAgIBATANBgkqhkiG9w0BAQsFADBgMQswCQYDVQQGEwJVUzERMA8GA1UE" +
                "CgwIQ2hyb21pdW0xIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXR" +
                "pb24xGjAYBgNVBAMMEUJhdGNoIENlcnRpZmljYXRlMB4XDTE3MDcxNDAyND" +
                "AwMFoXDTQyMTAzMTAwMjUyN1owYDELMAkGA1UEBhMCVVMxETAPBgNVBAoMC" +
                "ENocm9taXVtMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9u" +
                "MRowGAYDVQQDDBFCYXRjaCBDZXJ0aWZpY2F0ZTBZMBMGByqGSM49AgEGCCq" +
                "GSM49AwEHA0IABI1hfmXJUI5kvMVnOsgqZ5naPBRGaCwljEY//99Y39L6Pm" +
                "w3i1PXlcSk3/tBme3Xhi8jq68CA7S4kRugVpmU4QGjJTAjMAwGA1UdEwEB/" +
                "wQCMAAwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADRwAw" +
                "RAIgU6vi/FOE48VEzYx9HQnQZ7LBGWGI9h1Sb3p58XpqFFQCIB6sxzhIgqz" +
                "3KO3SWZIXNg4XPMIZ/wWvyqFib9YhwV/oaGF1dGhEYXRhWKRJlg3liA6MaH" +
                "Q0Fw9kdmBbj+SuuaKGMseZXPO6gx2XY0EAAAAAAAAAAAAAAAAAAAAAAAAAA" +
                "AAgw5ke5/1fAWcMvUKNppUEW+LwnkfkNZWfVcZkxPQbMwilAQIDJiABIVgg" +
                "GZLqtdXu3x82rGm0UINwsO+07YmkxilFuiAVAyJ7aYYiWCAXPzUwQg4ziYy" +
                "0Fbj+LC06NLxSh+vJi/7lAvwIhmRkvA==";
            var credentialId = "w5ke5/1fAWcMvUKNppUEW+LwnkfkNZWfVcZkxPQbMwg=";

            var credential = Credential.Decode(
                new CborData(Convert.FromBase64String(attestationObject)),
                new ClientData(Convert.FromBase64String(clientData), CoseHashAlgorithm.SHA_256),
                new CredentialId(Convert.FromBase64String(credentialId)),
                Transport.Test);

            AssertThat.IsTrue(credential.IsFidoU2F);

            AssertThat.IsNotNull(credential.AttestationStatement);
            AssertThat.AreEqual(CoseSignatureAlgorithm.ES256, credential.AttestationStatement!.Algorithm);
            AssertThat.IsFalse(credential.AttestationStatement.IsSelfAttested);

            AssertThat.IsNotNull(credential.AttestationStatement.Certificate);
            AssertThat.AreEqual(
                "CN=Batch Certificate, OU=Authenticator Attestation, O=Chromium, C=US",
                credential.AttestationStatement.Certificate!.Subject);

            AssertThat.IsTrue(credential.AuthenticatorData.Flags.HasFlag(AuthenticatorDataFlags.UserPresent));
            AssertThat.IsFalse(credential.AuthenticatorData.Flags.HasFlag(AuthenticatorDataFlags.UserVerified));
            AssertThat.IsTrue(credential.AuthenticatorData.Flags.HasFlag(AuthenticatorDataFlags.AttestedCredentialDataIncluded));

            AssertThat.IsNotNull(credential.AuthenticatorData.AttestedCredentialData);
            AssertThat.AreEqual(
                credential.Id,
                credential.AuthenticatorData.AttestedCredentialData!.CredentialId);
            AssertThat.AreEqual(
                Guid.Empty,
                credential.AuthenticatorData.AttestedCredentialData.Aaguid);

            credential.Verify();
        }
    }
}
