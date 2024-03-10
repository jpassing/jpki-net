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

using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Jpki.Security.Cryptography
{
    public static class X509Certificate2Extensions
    {

#if !NET7_0_OR_GREATER

        /// <summary>
        /// Export the certificate in PEM format.
        /// </summary>
        /// <param name="certificate"></param>
        /// <returns></returns>
        public static string ExportCertificatePem(
            this X509Certificate2 certificate)
        {
            return new PemEnvelope(
                PemEnvelope.DataFormat.Certificate,
                certificate.RawData).ToString();
        }

#endif

        /// <summary>
        /// Import a PEM-encoded certificate.
        /// </summary>
        public static X509Certificate2 CreateFromPem(string certPem)
        {
#if NET6_0_OR_GREATER
            return X509Certificate2.CreateFromPem(certPem);
#else
            if (string.IsNullOrEmpty(certPem))
            {
                throw new CryptographicException(
                    "The certificate is empty");
            }

            var envelope = PemEnvelope.Parse(certPem);
            if (envelope.Format != PemEnvelope.DataFormat.Certificate)
            {
                throw new CryptographicException(
                    "The certificate contents do not contain a PEM with a CERTIFICATE label");
            }

            return new X509Certificate2(envelope.Data);
#endif
        }


        /// <summary>
        /// Find an extension by OID. Returns null if not found.
        /// </summary>
        public static bool TryGetExtension(
            this X509Certificate2 certificate,
            Oid oid,
            [NotNullWhen(true)] out X509Extension? extension)
        {
            extension = certificate
                .ExpectNotNull(nameof(certificate))
                .Extensions
                .Cast<X509Extension>()
                .FirstOrDefault(e => e.Oid?.Value == oid.Value);

            return extension != null;
        }
    }
}
