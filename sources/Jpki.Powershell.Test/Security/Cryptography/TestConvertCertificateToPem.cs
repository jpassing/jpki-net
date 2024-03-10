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

using Jpki.Powershell.Security.Cryptography;
using Jpki.Powershell.Test.Runtime;
using Jpki.Security.Cryptography;
using NUnit.Framework;
using System;

namespace Jpki.Powershell.Test.Security.Cryptography
{
    [TestFixture]
    public class TestConvertCertificateToPem
    {
        private const string CertificatePem =
            @"-----BEGIN CERTIFICATE-----
            MIIB+jCCAWOgAwIBAgIUa/+VBrWwGQfeDOoRJTZuLmkdcxEwDQYJKoZIhvcNAQEL
            BQAwDzENMAsGA1UEAwwEdGVzdDAeFw0yMzEwMzAwODE4MDVaFw0yMzEwMzEwODE4
            MDVaMA8xDTALBgNVBAMMBHRlc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGB
            ALBquZdaJVLykbNhfzxpjl7voRmhmxQlGZo4JkCKmExBYSQMBz16KXg7R1SMF0Yh
            PF39E9IglcyDJan8gUNAn065IFseeuhfcZ8x7vU9KiYTr+T3IzgvVCvWKimltpA5
            KDpy+TthDV83nxaAHF02jkWsFHzBU9VsLbELL8SAW6BDAgMBAAGjUzBRMB0GA1Ud
            DgQWBBRL2VMqPGzO1c6SbGPHJ53O44tPHDAfBgNVHSMEGDAWgBRL2VMqPGzO1c6S
            bGPHJ53O44tPHDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4GBABmb
            v1HASwV9RplDMU4LuuMv5fOLbL3sy04ROcc4ycys8QFQKGtKA+nWrWHoPp9Y7qM2
            tzP5EGpo7mvyFyB9sao6r/SIA/rhXcffVUPUZTjrU7ltC3hd14z74QXTwZci5W/8
            T6i18XNKoNpxi12p/CEh83Ln1rR2ZNmcRUmRMNKc
            -----END CERTIFICATE-----";

        [Test]
        public void WhenCertificateIsNull_CmdletThrowsException(
            [Values("", "----", "-----BEGIN RSA PUBLIC KEY-----\n")] string pem)
        {
            var cmdlet = new ConvertCertificateToPem()
            {
                Certificate = null
            };

            CmdletAssert.ThrowsException<ArgumentNullException>(cmdlet);
        }

        [Test]
        public void WhenPemValid_CmdletReturnsCertificate()
        {
            var cmdlet = new ConvertCertificateToPem()
            {
                Certificate = X509Certificate2Extensions.CreateFromPem(CertificatePem)
            };

            var pem = CmdletAssert.WritesSingleObject<string>(cmdlet);
            
        }
    }
}
