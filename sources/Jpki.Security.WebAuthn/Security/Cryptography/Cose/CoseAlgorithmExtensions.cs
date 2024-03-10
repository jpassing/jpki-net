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

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Jpki.Security.Cryptography.Cose
{
    public static class CoseAlgorithmExtensions
    {
        //---------------------------------------------------------------------
        // CoseHashAlgorithm.
        //---------------------------------------------------------------------

        public static HashAlgorithmName GetName(
            this CoseHashAlgorithm hashAlgorithm)
        {
            switch (hashAlgorithm)
            {
                case CoseHashAlgorithm.SHA_256:
                    return HashAlgorithmName.SHA256;

                case CoseHashAlgorithm.SHA_384:
                    return HashAlgorithmName.SHA384;

                case CoseHashAlgorithm.SHA_512:
                    return HashAlgorithmName.SHA512;

                default:
                    throw new ArgumentException(
                        $"The hash algorithm {hashAlgorithm} is not supported");
            }
        }

        //---------------------------------------------------------------------
        // CoseSignatureAlgorithm.
        //---------------------------------------------------------------------

        /// <summary>
        /// Look up the hash algorithm used by a COSE signature
        /// algorithm.
        /// </summary>
        public static CoseHashAlgorithm GetHashAlgorithm(
            this CoseSignatureAlgorithm signatureAlgorithm)
        {
            switch (signatureAlgorithm)
            {
                case CoseSignatureAlgorithm.RS256:
                case CoseSignatureAlgorithm.PS256:
                case CoseSignatureAlgorithm.ES256:
                    return CoseHashAlgorithm.SHA_256;

                case CoseSignatureAlgorithm.RS384:
                case CoseSignatureAlgorithm.PS384:
                case CoseSignatureAlgorithm.ES384:
                    return CoseHashAlgorithm.SHA_384;

                case CoseSignatureAlgorithm.RS512:
                case CoseSignatureAlgorithm.PS512:
                case CoseSignatureAlgorithm.ES512:
                    return CoseHashAlgorithm.SHA_512;

                default:
                    throw new ArgumentException(
                        $"The signature algorithm {signatureAlgorithm} is not supported");
            }
        }

        /// <summary>
        /// Verify a signature ofer a blob of data.
        /// </summary>
        public static bool VerifySignature(
            this CoseSignatureAlgorithm signatureAlgorithm,
            byte[] data,
            byte[] signature,
            X509Certificate2 certificate)
        {
            switch (signatureAlgorithm)
            {
                case CoseSignatureAlgorithm.RS256:
                case CoseSignatureAlgorithm.RS384:
                case CoseSignatureAlgorithm.RS512:
                    using (var key = certificate.GetRSAPublicKey())
                    {
                        return key
                            .ExpectNotNull("The certificate does not contain a suitable public key")
                            .VerifyData(
                                data,
                                signature,
                                signatureAlgorithm.GetHashAlgorithm().GetName(),
                                RSASignaturePadding.Pkcs1);
                    }

                case CoseSignatureAlgorithm.PS256:
                case CoseSignatureAlgorithm.PS384:
                case CoseSignatureAlgorithm.PS512:
                    using (var key = certificate.GetRSAPublicKey())
                    {
                        return key
                            .ExpectNotNull("The certificate does not contain a suitable public key")
                            .VerifyData(
                                data,
                                signature,
                                signatureAlgorithm.GetHashAlgorithm().GetName(),
                                RSASignaturePadding.Pss);
                    }

                case CoseSignatureAlgorithm.ES256:
                case CoseSignatureAlgorithm.ES384:
                case CoseSignatureAlgorithm.ES512:
                    using (var key = certificate.GetECDsaPublicKey())
                    {
                        //
                        // NB. WebAuthN signatures are DER-formatted.
                        //
                        return key
                            .ExpectNotNull("The certificate does not contain a suitable public key")
                            .VerifyData(
                                data,
                                signature,
                                signatureAlgorithm.GetHashAlgorithm().GetName(),
                                DSASignatureFormat.Rfc3279DerSequence);
                    }

                default:
                    throw new ArgumentException(
                        $"The signature algorithm {signatureAlgorithm} is not supported");
            }
        }

        /// <summary>
        /// Look up the RSA signature padding used by a COSE signature
        /// algorithm.
        /// </summary>
        internal static RSASignaturePadding GetRSASignaturePadding(
            this CoseSignatureAlgorithm signatureAlgorithm)
        {
            switch (signatureAlgorithm)
            {
                case CoseSignatureAlgorithm.RS256:
                case CoseSignatureAlgorithm.RS384:
                case CoseSignatureAlgorithm.RS512:
                    return RSASignaturePadding.Pkcs1;

                case CoseSignatureAlgorithm.PS256:
                case CoseSignatureAlgorithm.PS384:
                case CoseSignatureAlgorithm.PS512:
                    return RSASignaturePadding.Pss;

                default:
                    throw new ArgumentException(
                        $"The signature algorithm {signatureAlgorithm} is not supported");
            }
        }
    }
}
