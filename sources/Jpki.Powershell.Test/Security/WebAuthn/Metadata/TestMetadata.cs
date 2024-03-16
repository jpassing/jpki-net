﻿using Jpki.Powershell.Runtime.Text;
using Jpki.Security.WebAuthn.Metadata;
using NUnit.Framework;
using System.Linq;

namespace Jpki.Security.WebAuthn.Security.WebAuthn.Metadata
{
    [TestFixture]
    internal class TestMetadata
    {
        /// <summary>
        /// Sample statement taken from the MDS.
        /// </summary>
        private readonly string MetadataStatement_YubiKey5ci = @"{
            ""legalHeader"": ""..."",
            ""attestationCertificateKeyIdentifiers"": [
              ""bf7bcaa0d0c6187a8c6abbdd16a15640e7c7bde2"",
              ""3012b66092a16d3d7687241634b20a3bde2634e8"",
              ""753300d65dcc73a39a7db31ef308db9fa0b566ae"",
              ""98552aea456370e22e1901e31817359142b92888"",
              ""b753a0e460fb2dc7c7c487e35f24cf63b065347c"",
              ""b6d44a4b8d4b0407872969b1f6b2263021be627e"",
              ""6d491f223af73cdf81784a6c0890f8a1d527a12c""
            ],
            ""description"": ""YubiKey 5 Series with Lightning"",
            ""authenticatorVersion"": 2,
            ""protocolFamily"": ""u2f"",
            ""schema"": 3,
            ""upv"": [
              {
                ""major"": 1,
                ""minor"": 1
              }
            ],
            ""authenticationAlgorithms"": [
              ""secp256r1_ecdsa_sha256_raw""
            ],
            ""publicKeyAlgAndEncodings"": [
              ""ecc_x962_raw""
            ],
            ""attestationTypes"": [
              ""basic_full""
            ],
            ""userVerificationDetails"": [
              [
                {
                  ""userVerificationMethod"": ""presence_internal""
                }
              ]
            ],
            ""keyProtection"": [
              ""hardware"",
              ""secure_element"",
              ""remote_handle""
            ],
            ""matcherProtection"": [
              ""on_chip""
            ],
            ""cryptoStrength"": 128,
            ""attachmentHint"": [
              ""external"",
              ""wired""
            ],
            ""tcDisplay"": [],
            ""attestationRootCertificates"": [
              ""MIIDHjCCAgagAwIBAgIEG0BT9zANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/jwYuhBVlqaiYWEMsrWFisgJ+PtM91eSrpI4TK7U53mwCIawSDHy8vUmk5N2KAj9abvT9NP5SMS1hQi3usxoYGonXQgfO6ZXyUA9a+KAkqdFnBnlyugSeCOep8EdZFfsaRFtMjkwz5Gcz2Py4vIYvCdMHPtwaz0bVuzneueIEz6TnQjE63Rdt2zbwnebwTG5ZybeWSwbzy+BJ34ZHcUhPAY89yJQXuE0IzMZFcEBbPNRbWECRKgjq//qT9nmDOFVlSRCt2wiqPSzluwn+v+suQEBsUjTGMEd25tKXXTkNW21wIWbxeSyUoTXwLvGS6xlwQSgNpk2qXYwf8iXg7VWZAgMBAAGjQjBAMB0GA1UdDgQWBBQgIvz0bNGJhjgpToksyKpP9xv9oDAPBgNVHRMECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAjvjuOMDSa+JXFCLyBKsycXtBVZsJ4Ue3LbaEsPY4MYN/hIQ5ZM5p7EjfcnMG4CtYkNsfNHc0AhBLdq45rnT87q/6O3vUEtNMafbhU6kthX7Y+9XFN9NpmYxr+ekVY5xOxi8h9JDIgoMP4VB1uS0aunL1IGqrNooL9mmFnL2kLVVee6/VR6C5+KSTCMCWppMuJIZII2v9o4dkoZ8Y7QRjQlLfYzd3qGtKbw7xaF1UsG/5xUb/Btwb2X2g4InpiB/yt/3CpQXpiWX/K4mBvUKiGn05ZsqeY1gx4g0xLBqcU9psmyPzK+Vsgw2jeRQ5JlKDyqE0hebfC1tvFu0CCrJFcw==""
            ],
            ""icon"": ""data:image/png;base64,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""
          },
          ""statusReports"": [
            {
              ""status"": ""FIDO_CERTIFIED_L1"",
              ""effectiveDate"": ""2020-05-12"",
              ""certificationDescriptor"": ""YubiKey 5Ci"",
              ""certificateNumber"": ""U2F110020191017007"",
              ""certificationPolicyVersion"": ""1.1.1"",
              ""certificationRequirementsVersion"": ""1.3""
            },
            {
              ""status"": ""FIDO_CERTIFIED"",
              ""effectiveDate"": ""2020-05-12""
            }
          ],
          ""timeOfLastStatusChange"": ""2020-05-12""
        }";

        /// <summary>
        /// Sample statement taken from the MDS.
        /// </summary>
        private const string MetadataStatement_YubiKey5Nfc = @"{
            ""legalHeader"": ""..."",
            ""aaguid"": ""fa2b99dc-9e39-4257-8f92-4a30d23c4118"",
            ""description"": ""YubiKey 5 Series with NFC"",
            ""authenticatorVersion"": 50100,
            ""protocolFamily"": ""fido2"",
            ""schema"": 3,
            ""upv"": [
              {
                ""major"": 1,
                ""minor"": 0
              }
            ],
            ""authenticationAlgorithms"": [
              ""ed25519_eddsa_sha512_raw"",
              ""secp256r1_ecdsa_sha256_raw""
            ],
            ""publicKeyAlgAndEncodings"": [
              ""cose""
            ],
            ""attestationTypes"": [
              ""basic_full""
            ],
            ""userVerificationDetails"": [
              [
                {
                  ""userVerificationMethod"": ""passcode_external"",
                  ""caDesc"": {
                    ""base"": 64,
                    ""minLength"": 4,
                    ""maxRetries"": 8,
                    ""blockSlowdown"": 0
                  }
                }
              ],
              [
                {
                  ""userVerificationMethod"": ""none""
                }
              ],
              [
                {
                  ""userVerificationMethod"": ""passcode_external""
                },
                {
                  ""userVerificationMethod"": ""presence_internal"",
                  ""caDesc"": {
                    ""base"": 64,
                    ""minLength"": 4,
                    ""maxRetries"": 8,
                    ""blockSlowdown"": 0
                  }
                }
              ],
              [
                {
                  ""userVerificationMethod"": ""presence_internal""
                }
              ]
            ],
            ""keyProtection"": [
              ""hardware"",
              ""secure_element""
            ],
            ""matcherProtection"": [
              ""on_chip""
            ],
            ""cryptoStrength"": 128,
            ""attachmentHint"": [
              ""external"",
              ""wired"",
              ""wireless"",
              ""nfc""
            ],
            ""tcDisplay"": [],
            ""attestationRootCertificates"": [
              ""MIIDHjCCAgagAwIBAgIEG0BT9zANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/jwYuhBVlqaiYWEMsrWFisgJ+PtM91eSrpI4TK7U53mwCIawSDHy8vUmk5N2KAj9abvT9NP5SMS1hQi3usxoYGonXQgfO6ZXyUA9a+KAkqdFnBnlyugSeCOep8EdZFfsaRFtMjkwz5Gcz2Py4vIYvCdMHPtwaz0bVuzneueIEz6TnQjE63Rdt2zbwnebwTG5ZybeWSwbzy+BJ34ZHcUhPAY89yJQXuE0IzMZFcEBbPNRbWECRKgjq//qT9nmDOFVlSRCt2wiqPSzluwn+v+suQEBsUjTGMEd25tKXXTkNW21wIWbxeSyUoTXwLvGS6xlwQSgNpk2qXYwf8iXg7VWZAgMBAAGjQjBAMB0GA1UdDgQWBBQgIvz0bNGJhjgpToksyKpP9xv9oDAPBgNVHRMECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAjvjuOMDSa+JXFCLyBKsycXtBVZsJ4Ue3LbaEsPY4MYN/hIQ5ZM5p7EjfcnMG4CtYkNsfNHc0AhBLdq45rnT87q/6O3vUEtNMafbhU6kthX7Y+9XFN9NpmYxr+ekVY5xOxi8h9JDIgoMP4VB1uS0aunL1IGqrNooL9mmFnL2kLVVee6/VR6C5+KSTCMCWppMuJIZII2v9o4dkoZ8Y7QRjQlLfYzd3qGtKbw7xaF1UsG/5xUb/Btwb2X2g4InpiB/yt/3CpQXpiWX/K4mBvUKiGn05ZsqeY1gx4g0xLBqcU9psmyPzK+Vsgw2jeRQ5JlKDyqE0hebfC1tvFu0CCrJFcw==""
            ],
            ""icon"": ""data:image/png;base64,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"",
            ""authenticatorGetInfo"": {
              ""versions"": [
                ""U2F_V2"",
                ""FIDO_2_0""
              ],
              ""extensions"": [
                ""hmac-secret""
              ],
              ""aaguid"": ""fa2b99dc9e3942578f924a30d23c4118"",
              ""options"": {
                ""plat"": false,
                ""rk"": true,
                ""clientPin"": true,
                ""up"": true
              },
              ""maxMsgSize"": 1200,
              ""pinUvAuthProtocols"": [
                1
              ]
            }
          },
          ""statusReports"": [
            {
              ""status"": ""FIDO_CERTIFIED_L1"",
              ""effectiveDate"": ""2020-05-12"",
              ""certificationDescriptor"": ""YubiKey Series 5 with NFC"",
              ""certificateNumber"": ""FIDO20020180918001"",
              ""certificationPolicyVersion"": ""1.1.0"",
              ""certificationRequirementsVersion"": ""1.2""
            },
            {
              ""status"": ""FIDO_CERTIFIED"",
              ""effectiveDate"": ""2020-05-12""
            }
          ],
          ""timeOfLastStatusChange"": ""2020-05-12""
        }";

        [Test]
        public void YubiKey5ci()
        {
            var statement = Json.Deserialize<MetadataStatement>(MetadataStatement_YubiKey5ci)!;

            AssertThat.NotNull(statement);
            AssertThat.AreEqual("...", statement.LegalHeader);
            AssertThat.AreEqual("YubiKey 5 Series with Lightning", statement.Description);
            CollectionAssertThat.AreEquivalent(
                new[] { "secp256r1_ecdsa_sha256_raw" }, 
                statement.AuthenticationAlgorithms);
            CollectionAssertThat.AreEquivalent(
                new[] { "hardware", "secure_element", "remote_handle" },
                statement.KeyProtection);
            AssertThat.AreEqual("u2f", statement.ProtocolFamily);
            AssertThat.AreEqual(1, statement.Upv.First().Major);
            AssertThat.AreEqual(1, statement.Upv.First().Minor);
            CollectionAssertThat.AreEquivalent(
                new[] { new[] { new UserVerificationDetails("presence_internal") } },
                statement.UserVerificationDetails);
        }

        [Test]
        public void YubiKey5Nfc()
        {
            var statement = Json.Deserialize<MetadataStatement>(MetadataStatement_YubiKey5Nfc)!;

            AssertThat.NotNull(statement);
            AssertThat.AreEqual("...", statement.LegalHeader);
            AssertThat.AreEqual("YubiKey 5 Series with NFC", statement.Description);
            CollectionAssertThat.AreEquivalent(
                new[] { "ed25519_eddsa_sha512_raw", "secp256r1_ecdsa_sha256_raw" },
                statement.AuthenticationAlgorithms);
            CollectionAssertThat.AreEquivalent(
                new[] { "hardware", "secure_element" },
                statement.KeyProtection);
            AssertThat.AreEqual("fido2", statement.ProtocolFamily);
            AssertThat.AreEqual(1, statement.Upv.First().Major);
            AssertThat.AreEqual(0, statement.Upv.First().Minor);
            CollectionAssertThat.AreEquivalent(
                new[] {
                    new[] { new UserVerificationDetails("passcode_external") },
                    new[] { new UserVerificationDetails("none") },
                    new[] { 
                        new UserVerificationDetails("passcode_external"), 
                        new UserVerificationDetails("presence_internal") 
                    },
                    new[] { new UserVerificationDetails("presence_internal") }
                },
                statement.UserVerificationDetails);
        }
    }
}
