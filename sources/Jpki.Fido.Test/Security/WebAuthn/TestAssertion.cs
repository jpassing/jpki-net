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
    public class TestAssertion
    {
        //
        // NB. Assertions have been created using the Chrome simulator.
        //

        [Test]
        public void WhenCtap2AssertionValid_ThenVerifySucceeds()
        {
            var attestationObject = "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2l" +
                "nWEYwRAIgV7YwembMjM+4q35oLHZ3Nhx3HvsEHc4ZSljnjTcRQL8CIHzeoc" +
                "0+p7XJfrYnXTA2TXboUBov6tl4XC179GJHNhEPY3g1Y4FZAd8wggHbMIIBf" +
                "aADAgECAgEBMA0GCSqGSIb3DQEBCwUAMGAxCzAJBgNVBAYTAlVTMREwDwYD" +
                "VQQKDAhDaHJvbWl1bTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3R" +
                "hdGlvbjEaMBgGA1UEAwwRQmF0Y2ggQ2VydGlmaWNhdGUwHhcNMTcwNzE0MD" +
                "I0MDAwWhcNNDIxMDMxMDE0MzIyWjBgMQswCQYDVQQGEwJVUzERMA8GA1UEC" +
                "gwIQ2hyb21pdW0xIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRp" +
                "b24xGjAYBgNVBAMMEUJhdGNoIENlcnRpZmljYXRlMFkwEwYHKoZIzj0CAQY" +
                "IKoZIzj0DAQcDQgAEjWF+ZclQjmS8xWc6yCpnmdo8FEZoLCWMRj//31jf0v" +
                "o+bDeLU9eVxKTf+0GZ7deGLyOrrwIDtLiRG6BWmZThAaMlMCMwDAYDVR0TA" +
                "QH/BAIwADATBgsrBgEEAYLlHAIBAQQEAwIFIDANBgkqhkiG9w0BAQsFAANJ" +
                "ADBGAiEAwapdz71K254ZtC80wBYMfbNJgq8gqV+EGeDr3uR1XcoCIQDuha3" +
                "DofLCn3l6fjBboe9RgAqFuPBXKMrKI96drOGEMWhhdXRoRGF0YVikSZYN5Y" +
                "gOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NBAAAAAQECAwQFBgcIAQIDB" +
                "AUGBwgAICmNlNz1nPODJFNPmX70dmo3IiprKaDn+xua63rPdVoVpQECAyYg" +
                "ASFYIOd0OpIhcgFJeO8jIeuWqxTAzkfe0aH/ZG6E7bxNNiXWIlggkplxKm9" +
                "n6web2JJu08ERDy4SWDDkLO8oYCcj95DOXr8=";

            var clientData = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIj" +
                "oiY21GdVpHOXRJR05vWVd4c1pXNW5aUSIsIm9yaWdpbiI6Imh0dHA6Ly9sb" +
                "2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0=";
            var authData = "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MBAAAAAg==";
            var signature = "MEUCID7CoIldp48zwP1c86BOPThRve2UV17SWucRGGb1Mo/" +
                "QAiEA7LcKvcYG63ujvR3nwJlymZyEEyKSbfFkRATNxh45tig=";
            var credentialId = "KY2U3PWc84MkU0+ZfvR2ajciKmspoOf7G5rres91WhU=";

            var attestation = Credential.Decode(
                new CborData(Convert.FromBase64String(attestationObject)),
                ClientData.FromJson("{}"),
                new CredentialId(Convert.FromBase64String(credentialId)),
                Transport.Test);

            var assertion = new Assertion(
                new ClientData(Convert.FromBase64String(clientData), CoseHashAlgorithm.SHA_256),
                new AuthenticatorData(Convert.FromBase64String(authData)),
                null,
                new CredentialId(Convert.FromBase64String(credentialId)),
                Convert.FromBase64String(signature));


            Assert.IsTrue(assertion.AuthenticatorData.Flags.HasFlag(AuthenticatorDataFlags.UserPresent));
            Assert.IsNull(assertion.AuthenticatorData.AttestedCredentialData);

            Assert.IsNotNull(attestation.AuthenticatorData.AttestedCredentialData);
            Assert.IsTrue(assertion.Verify(attestation.AuthenticatorData.AttestedCredentialData!.Key));
        }

        [Test]
        public void WhenU2fAssertionValid_ThenVerifySucceeds()
        {
            var attestationObject = "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWE" +
                "cwRQIhAMJHK4EMvGZ4t9j0/ssLCaSXw5qbHiug1mya2/5+ChrHAiAoCx2e" +
                "gojTaAz60cOW6Ej3qWlVwGbOI3MhfSUDwlU6H2N4NWOBWQHfMIIB2zCCAX" +
                "2gAwIBAgIBATANBgkqhkiG9w0BAQsFADBgMQswCQYDVQQGEwJVUzERMA8G" +
                "A1UECgwIQ2hyb21pdW0xIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZX" +
                "N0YXRpb24xGjAYBgNVBAMMEUJhdGNoIENlcnRpZmljYXRlMB4XDTE3MDcx" +
                "NDAyNDAwMFoXDTQyMTAzMTAxNDYxOVowYDELMAkGA1UEBhMCVVMxETAPBg" +
                "NVBAoMCENocm9taXVtMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVz" +
                "dGF0aW9uMRowGAYDVQQDDBFCYXRjaCBDZXJ0aWZpY2F0ZTBZMBMGByqGSM" +
                "49AgEGCCqGSM49AwEHA0IABI1hfmXJUI5kvMVnOsgqZ5naPBRGaCwljEY/" +
                "/99Y39L6Pmw3i1PXlcSk3/tBme3Xhi8jq68CA7S4kRugVpmU4QGjJTAjMA" +
                "wGA1UdEwEB/wQCMAAwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcN" +
                "AQELBQADSQAwRgIhALmtxjy2zDdGpkkxUfiShT1ZDH7zkjYZzFO8xPfwrx" +
                "IXAiEA7cKdy+3sBIbzA8MA6WtoCtDJSh+kmGEsfzK8qRapccNoYXV0aERh" +
                "dGFYpEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAA" +
                "AAAAAAAAAAAAAAAAAAACBuO0DkhyWfSMAN1QaV6CpPdg0fIR7plfj3wqoC" +
                "FgBgoKUBAgMmIAEhWCAzGe/hQvOejdRcoj3YKFXmq6Vndefb74IqZRpH09" +
                "kdNSJYICSiOJFgEJGwcUDCUFIbVjYzwZOzHAMUi6N4WutoTI0c";

            var clientData = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlI" +
                "joiY21GdVpHOXRJR05vWVd4c1pXNW5aUSIsIm9yaWdpbiI6Imh0dHA6Ly9" +
                "sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa" +
                "2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWV" +
                "udERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ" +
                "29vLmdsL3lhYlBleCJ9";
            var authData = "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MBAAAAAg==";
            var signature = "MEQCIGO2kUq/0YtmZx9PPhmkKgqvhJoSBhtbkdeOy9QwM2" +
                "PMAiBZNzNG8SsT5E03bBsvssSbapgHsVkF/69v1FhII+idUg==";
            var credentialId = "bjtA5Icln0jADdUGlegqT3YNHyEe6ZX498KqAhYAYKA=";

            var attestation = Credential.Decode(
                new CborData(Convert.FromBase64String(attestationObject)),
                ClientData.FromJson("{}"),
                new CredentialId(Convert.FromBase64String(credentialId)),
                Transport.Test);

            var assertion = new Assertion(
                new ClientData(Convert.FromBase64String(clientData), CoseHashAlgorithm.SHA_256),
                new AuthenticatorData(Convert.FromBase64String(authData)),
                null,
                new CredentialId(Convert.FromBase64String(credentialId)),
                Convert.FromBase64String(signature));


            Assert.IsTrue(assertion.AuthenticatorData.Flags.HasFlag(AuthenticatorDataFlags.UserPresent));
            Assert.IsNull(assertion.AuthenticatorData.AttestedCredentialData);

            Assert.IsNotNull(attestation.AuthenticatorData.AttestedCredentialData);
            Assert.IsTrue(assertion.Verify(attestation.AuthenticatorData.AttestedCredentialData!.Key));
        }

        [Test]
        public void WhenAttestedCredentialDataIsNull_ThenVerifyThrowsException()
        {
            var clientData = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlI" +
                "joiY21GdVpHOXRJR05vWVd4c1pXNW5aUSIsIm9yaWdpbiI6Imh0dHA6Ly9" +
                "sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa" +
                "2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWV" +
                "udERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ" +
                "29vLmdsL3lhYlBleCJ9";
            var authData = "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MBAAAAAg==";
            var signature = "MEQCIGO2kUq/0YtmZx9PPhmkKgqvhJoSBhtbkdeOy9QwM2" +
                "PMAiBZNzNG8SsT5E03bBsvssSbapgHsVkF/69v1FhII+idUg==";
            var credentialId = "bjtA5Icln0jADdUGlegqT3YNHyEe6ZX498KqAhYAYKA=";

            var assertion = new Assertion(
                new ClientData(Convert.FromBase64String(clientData), CoseHashAlgorithm.SHA_256),
                new AuthenticatorData(Convert.FromBase64String(authData)),
                null,
                new CredentialId(Convert.FromBase64String(credentialId)),
                Convert.FromBase64String(signature));

            var credential = new Credential(
                "test",
                ClientData.FromJson("{}"),
                new AuthenticatorData(Convert.FromBase64String(authData)),
                new CredentialId(new byte[] { 1 }),
                null,
                Transport.Test);

            Assert.Throws<InvalidAttestationException>(() => assertion.Verify(credential));
        }
    }
}
