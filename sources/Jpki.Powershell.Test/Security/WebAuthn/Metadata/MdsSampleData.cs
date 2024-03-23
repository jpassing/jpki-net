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

namespace Jpki.Powershell.Test.Security.WebAuthn.Metadata
{
    /// <summary>
    /// Sample data taken from the MDS.
    /// </summary>
    internal static class MdsSampleData
    {
        internal static class MetadataStatements
        {
            internal const string YubiKey5ci = @"{
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
              }";

            internal const string YubiKey5Nfc = @"{
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
              }";

        }

        internal static class MetadataBlobs
        {
            public const string GoogleTitanV2 = @"{
                ""legalHeader"": ""..."",
                ""no"": 64,
                ""nextUpdate"": ""2024-04-01"",
                ""entries"": [
                {
                    ""aaguid"": ""42b4fb4a-2866-43b2-9bf7-6c6669c2e5d3"",
                    ""metadataStatement"": {
                        ""legalHeader"": ""Submission of ..."",
                        ""aaguid"": ""42b4fb4a-2866-43b2-9bf7-6c6669c2e5d3"",
                        ""description"": ""Google Titan Security Key v2"",
                        ""authenticatorVersion"": 1,
                        ""protocolFamily"": ""fido2"",
                        ""schema"": 3,
                        ""upv"": [
                            {
                            ""major"": 1,
                            ""minor"": 0
                            }
                        ],
                        ""authenticationAlgorithms"": [ ""secp256r1_ecdsa_sha256_raw"" ],
                        ""publicKeyAlgAndEncodings"": [ ""ecc_x962_raw"", ""cose"" ],
                        ""attestationTypes"": [ ""basic_full"" ],
                        ""userVerificationDetails"": [
                            [
                            { ""userVerificationMethod"": ""presence_internal"" },
                            {
                                ""userVerificationMethod"": ""passcode_external"",
                                ""caDesc"": {
                                ""base"": 10,
                                ""minLength"": 4,
                                ""maxRetries"": 0,
                                ""blockSlowdown"": 0
                                }
                            }
                            ],
                            [ { ""userVerificationMethod"": ""presence_internal"" } ],
                            [ { ""userVerificationMethod"": ""none"" } ],
                            [
                            {
                                ""userVerificationMethod"": ""passcode_external"",
                                ""caDesc"": {
                                ""base"": 10,
                                ""minLength"": 4,
                                ""maxRetries"": 0,
                                ""blockSlowdown"": 0
                                }
                            }
                            ]
                        ],
                        ""keyProtection"": [ ""hardware"", ""secure_element"" ],
                        ""matcherProtection"": [ ""on_chip"" ],
                        ""cryptoStrength"": 128,
                        ""attachmentHint"": [ ""external"", ""wired"", ""wireless"", ""nfc"" ],
                        ""tcDisplay"": [],
                        ""attestationRootCertificates"": [ ""MIICIjCCAcigAwIBAgIBAjAKBggqhkjOPQQDAjBkMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGR29vZ2xlMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMSAwHgYDVQQDDBdUaXRhbiBTZWN1cml0eSBLZXkgUm9vdDAgFw0yMTEyMDExNTI2MzFaGA8yMTIxMTIwMjE1MjYzMVowZzELMAkGA1UEBhMCVVMxDzANBgNVBAoMBkdvb2dsZTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEjMCEGA1UEAwwaVGl0YW4gU2VjdXJpdHkgS2V5IFNpZ25pbmcwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARGSX/0WmoStYfhmlzSPB4SARhmTBpPi0o3yYygS4smn/4OFdGNJdsPxkub62pOlWe0I6cJSh9W3EAHA2ZPO+S+o2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQURTqQYOsPJ897X40vav+XoW+S6sgwHwYDVR0jBBgwFoAU2d6JrFCoEZAe/LUpIMybltDsMh0wCgYIKoZIzj0EAwIDSAAwRQIgSr3N14HdtCfj7QZ0R7kWg6I317QENb8q+fbNko6nK4oCIQD5Jh14grDc6F7gHib9QTv8sUs6w8gF1JYKMK+LDOYPYg=="", ""MIICMjCCAdmgAwIBAgIBATAKBggqhkjOPQQDAjBkMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGR29vZ2xlMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMSAwHgYDVQQDDBdUaXRhbiBTZWN1cml0eSBLZXkgUm9vdDAgFw0yMTEyMDExNTIzNTFaGA8yMTIxMTIwMjE1MjM1MVowZDELMAkGA1UEBhMCVVMxDzANBgNVBAoMBkdvb2dsZTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEgMB4GA1UEAwwXVGl0YW4gU2VjdXJpdHkgS2V5IFJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARqmNWzcDNH63o8TzodB2jk9b49VPsfIvXpdhaWxfLayo4LBbDrXyxF3JR1P6W6ZsqWCEYrX0oYIxAog3hCE4ydo3oweDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU2d6JrFCoEZAe/LUpIMybltDsMh0wHwYDVR0jBBgwFoAU2d6JrFCoEZAe/LUpIMybltDsMh0wFQYLKwYBBAGC5RwCAQEEBgQEAwIAADAKBggqhkjOPQQDAgNHADBEAiANIQ48/nMp2KfYNiovcyxWXJLiul4Sv+zcRJezrd/WWAIgVucQ531fqzY7ODoK+dIDykRudvlW/yBqza/AdS0Sq6Q="" ],
                        ""icon"": ""data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAYAAABXAvmHAAAD1ElEQVR4AeyXU5gcTRSG62L927b/aJLpnt241zGmd2Pbxl1s29Yotm3bdqY3nN5oUakTq43leZ5v2Xi/qoMalBkiO84xTND1qNAwbyTdkshBtM4bZTtFvp97Tdu4SHo6UVu4Fu5Jc3AA4aKo0QTuNhFWKI5oPDzDdHACzcCKAog+gh2zFjIc/CYT+iN52TIibIQgxW4zlk8NSheq7PNtxwbrku5p5Y2gu8PDTdQDLspWUh/4KHqwqfCgCPqYl6G/NXLl0z/8jSiK1Qhz+7UZwJkKnxBj/dcbafMpBE56PsQqvq+TwN+eL4oDrjUMHoKLpFcphJ+s5OXXmLBfyQJ5DIGHdqlkml6PpiORyoCjB4E/pBs8Xof8+EHfnuCKWVNkwF+DVNP8TobxQ3pF8qoANmm1P37o/AgnxOcRgbf5rsdQOVF6i6TVAcvAAOjx0kB8p/HfQiYqpjd2SJ8vCXgSwL8uvucP2BtNvQ6/DKXHSF4dUBGA36cHkz7DCWUtAI+5aBuVPg2s8h8OsEJ6ND8EUuooSq9BILcBqLj82iKFEdGTx3oqvAe/TKiAr0kZeLzSn0pjA6BzQjuApUQK/cN0YCBJtQEEkfYGcJY1ACkUlJ4NcDKK2JKeDeySNLDav2E6MHBJYBL7jxeD51cFJfeel2+pCgOT5Qp6vOQc6MWvEjJQUwj+9IrPcAVPDKacLLbOYv9FBkVkT76t5A70ShwucJgL/vF98CuW/IyLuMoC/DM52OnGGfBtkzIQ2cNXUew4sekF+MPVAbjfgrwA/Y5oR1yk3vDhPRLLyqkBph//LYIQS6PrKz/CdWczACuka6Ez7D/qBc908X5I4I5J5n/PxE1SnwmCNi79/kasuyRASukY7Y7X5bNsRE/fPDmrT1KsKZIKymGvC4AydYpyls+paeV78Itkts/bTBcsb5ASsF0KTDygXPbOzORaiqZ0PhcbGzax65HwPl6Z/T+xs/yHO+1hBCwJAOXLztFOtjfcK/hcd/yflINtSq7b9uI+2/TGmBlwVPIILbD6wgEvgheo1G2ifUTrQAAMBoWup2dVwYWGLRcpXj4WqQmrk50MLzBLBcaOJIPq7psGevi6q29v6xg/yhXnMdOEbWo7HN733Iu895DU8QMWTSZg+pppgp5V7XHRwVtfwOsTJI9bQscxx0TcYFg4pHeQwWUhLzhkGDgUuotlkZEBK2N1sTVJgZ/TEf4BeWZ/y7xynyKzAgYX7bBXJEW+THpmCOqU1RHX0Tqr8pcoLQMOdmAGchd6/vPdSXonPWDCPxmwQADibHC/YhiAUQAA0S0KWSVGA04AAAAASUVORK5CYII="",
                        ""supportedExtensions"": [
                            {
                            ""id"": ""hmac-secret"",
                            ""fail_if_unknown"": false
                            },
                            {
                            ""id"": ""credProtect"",
                            ""fail_if_unknown"": false
                            }
                        ],
                        ""authenticatorGetInfo"": {
                            ""versions"": [ ""FIDO_2_0"", ""U2F_V2"" ],
                            ""extensions"": [ ""credProtect"", ""hmac-secret"" ],
                            ""aaguid"": ""42b4fb4a286643b29bf76c6669c2e5d3"",
                            ""options"": {
                            ""rk"": true,
                            ""clientPin"": false
                            },
                            ""maxMsgSize"": 2200,
                            ""pinUvAuthProtocols"": [ 1 ]
                        }
                    },
                    ""statusReports"": [
                        {
                            ""status"": ""FIDO_CERTIFIED_L1"",
                            ""effectiveDate"": ""2023-06-12"",
                            ""certificationDescriptor"": ""Google Titan Security Key v2"",
                            ""certificateNumber"": ""FIDO20020230612002"",
                            ""certificationPolicyVersion"": ""1.4.0"",
                            ""certificationRequirementsVersion"": ""1.5.0""
                        },
                        {
                            ""status"": ""FIDO_CERTIFIED"",
                            ""effectiveDate"": ""2023-06-12""
                        }
                    ],
                    ""timeOfLastStatusChange"": ""2023-09-03""
                }
                ]
            }";
        }
    }
}