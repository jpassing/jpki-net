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
using Jpki.Security.Cryptography;
using Jpki.Security.Cryptography.Cose;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace Jpki.Security.WebAuthn
{
    /// <summary>
    /// Signed data object containing statements about a public key credential
    /// and the authenticator that created it
    /// </summary>
    public class AttestationStatement
    {
        private readonly bool isFidoU2f;

        /// <summary>
        /// Attestation signature that was created using the key of the attesting
        /// authority (except for the case of self attestation, when it is created
        /// using the credential private key).
        /// </summary>
        private readonly byte[] signature;

        public CoseSignatureAlgorithm Algorithm { get; }

        public ICollection<X509Certificate2>? CertificateChain { get; }

        public X509Certificate2? Certificate => this.CertificateChain?.FirstOrDefault();

        internal AttestationStatement(
            CoseSignatureAlgorithm algorithm,
            byte[] signature,
            ICollection<X509Certificate2>? certificateChain,
            bool isFidoU2f)
        {
            this.Algorithm = algorithm;
            this.signature = signature.ExpectNotNull(nameof(signature));
            this.CertificateChain = certificateChain;
            this.isFidoU2f = isFidoU2f;
        }

        /// <summary>
        /// If x5c is not present, self attestation is in use.
        /// </summary>
        public bool IsSelfAttested => this.Certificate == null;

        //---------------------------------------------------------------------
        // Verification.
        //---------------------------------------------------------------------

        private bool VerifySignature(
            AuthenticatorData authenticatorData,
            ClientData clientData)
        {
            if (this.Certificate == null)
            {
                throw new InvalidOperationException(
                    "The attestation does not include a certificate and " +
                    "cannot be verified");
            }

            //
            // The signature rules differ between U2F and CTAP2/WebAuthN.
            //
            if (this.isFidoU2f)
            {
                //
                // Follow U2F rules, see
                // https://fidoalliance.org/specs/fido-u2f-v1.0-nfc-bt-amendment-20150514/fido-u2f-raw-message-formats.html
                // (section 4.3).
                //
                // The signature is over the following byte string:
                //
                // - A byte reserved for future use[1 byte] with the value 0x00.
                //   This will evolve into a byte that will allow RPs to track
                //   known-good applet version of U2F tokens from specific vendors.
                // 
                // - The application parameter[32 bytes] from the registration
                //   request message.
                // 
                // - The challenge parameter[32 bytes] from the registration
                //   request message.
                // 
                // - The above key handle[variable length]. (Note that the key
                //   handle length is not included in the signature base string.
                // 
                // - The above user public key [65 bytes].
                //

                if (authenticatorData.AttestedCredentialData == null)
                {
                    throw new InvalidOperationException(
                        "The attestation lacks attested credential data and " +
                        "cannot be verified");
                }

                //
                // Use the uncompressed x,y-representation of a curve point.
                //
                var key = (CoseEcdsaPublicKey)authenticatorData.AttestedCredentialData.Key;
                var keyPoint = key.Key.ExportParameters(false).Q;
                var publicKey = new byte[] { 0x04 }
                    .Concat(keyPoint.X.AssumeNotNull())
                    .Concat(keyPoint.Y.AssumeNotNull())
                    .ToArray(); ;

                Debug.Assert(publicKey.Length == 65);

                var signatureBase = new byte[] { 0x00 }
                    .Concat(authenticatorData.RelyingPartyIdHash)
                    .Concat(clientData.Hash)
                    .Concat(authenticatorData.AttestedCredentialData.CredentialId.Value)
                    .Concat(publicKey)
                    .ToArray();

                return this.Algorithm.VerifySignature(
                    signatureBase,
                    this.signature,
                    this.Certificate);
            }
            else
            {
                //
                // Follow WebAuthN rules.
                //
                // Verify that sig is a valid signature over the concatenation
                // of authenticatorData and clientDataHash using the attestation
                // public key in attestnCert with the algorithm specified in alg.
                //
                var signatureBase = authenticatorData.Value
                    .Concat(clientData.Hash)
                    .ToArray();

                return this.Algorithm.VerifySignature(
                    signatureBase,
                    this.signature,
                    this.Certificate);
            }
        }

        /// <summary>
        /// Verify that the attestation is well-formed and that the
        /// signature is valid.
        /// </summary>
        internal void Verify(
            AuthenticatorData authenticatorData,
            ClientData clientData)
        {
            //
            // (1) Verify that attStmt is valid CBOR conforming to the syntax
            //     defined above and perform CBOR decoding on it to extract
            //     the contained fields.
            //
            //     webauthn.dll did the decoding for us, so there's nothing
            //     left to do.
            // 
            // (2) If x5c is present:
            // 
            if (this.Certificate != null)
            {
                //
                // Verify that sig is a valid signature over the concatenation
                // of authenticatorData and clientDataHash using the attestation
                // public key in attestnCert with the algorithm specified in alg.
                //
                if (!VerifySignature(authenticatorData, clientData))
                {
                    throw new InvalidAttestationException("The signature is invalid");
                }

                if (!this.isFidoU2f)
                {
                    //
                    // Verify that attestnCert meets the requirements in § 8.2.1
                    // Packed Attestation Statement Certificate Requirements.
                    //
                    if (!this.Certificate.TryGetExtension(Oids.BasicConstraints, out var basicConstraintsExt))
                    {
                        throw new InvalidAttestationException(
                            "The cerfificate does not contain a basic constraints extension");
                    }
                    else if (((X509BasicConstraintsExtension)basicConstraintsExt!).CertificateAuthority)
                    {
                        throw new InvalidAttestationException(
                            "The cerfificate is a CA certificate");
                    }
                }

                if (this.Certificate.TryGetExtension(Oids.FidoGenCeAaguid, out var aaguidExt) &&
                    authenticatorData.AttestedCredentialData != null)
                {
                    //
                    // If attestnCert contains an extension with
                    // OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify
                    // that the value of this extension matches the aaguid in authenticatorData.
                    //     
                    // NB. The GUID must be prefixed with 00 10 (DER for 16 byte string).
                    //
                    if (aaguidExt.RawData.Length != Marshal.SizeOf<Guid>() + 2 ||
                        aaguidExt.RawData[0] != 0x04 || aaguidExt.RawData[1] != 0x10)
                    {
                        throw new InvalidAttestationException(
                            "The attestation certificate contains a malformed " +
                            "id-fido-gen-ce-aaguid extension");
                    }

                    var aaguid = new byte[Marshal.SizeOf<Guid>()];
                    Array.Copy(aaguidExt.RawData, 2, aaguid, 0, aaguid.Length);
                    if (new Guid(aaguid) != authenticatorData.AttestedCredentialData.Aaguid)
                    {
                        throw new InvalidAttestationException(
                            "The AAGUID in the attestation certificate does not match" +
                            "the AAGUID in the authenticator data");
                    }
                }
            }
            else
            {
                //     
                // (3) If x5c is not present, self attestation is in use.
                //     
                //  -  Validate that alg matches the algorithm of the credentialPublicKey
                //     in authenticatorData.
                //     
                //  -  Verify that sig is a valid signature over the concatenation of
                //     authenticatorData and clientDataHash using the credential public
                //     key with alg.
                //     
                //  -  If successful, return implementation-specific values representing
                //     attestation type Self and an empty attestation trust path.
                //
                throw new NotImplementedException();
            }
        }

        //---------------------------------------------------------------------
        // Factory methods.
        //---------------------------------------------------------------------

        /// <summary>
        /// Decode attestation statement from CBOR.
        /// </summary>
        internal static CborDataItem Decode(
            string format,
            CborDataItem dataItem,
            out AttestationStatement? statement)
        {
            //
            // NB. U2F statements don't include an 'alg' field,
            // therefore assume ES256 by default.
            //
            long alg = 0;
            byte[] sig = null;
            ICollection<X509Certificate2> x5c = null;

            Debug.Assert(!Enum.IsDefined(typeof(CoseSignatureAlgorithm), (int)alg));

            var nextItem = dataItem.ReadMapStart(out var mapLength);
            for (var mapIndex = 0;
                mapIndex < mapLength && !nextItem.IsBreak;
                mapIndex++)
            {
                nextItem = nextItem.ReadTextString(out var key);
                switch (key)
                {
                    case "alg":
                        //
                        // A COSEAlgorithmIdentifier containing the identifier of
                        // the algorithm used to generate the attestation signature.
                        //
                        nextItem = nextItem.ReadNegativeInteger(out alg);
                        break;

                    case "sig":
                        //
                        // A byte string containing the attestation signature.
                        //
                        nextItem = nextItem.ReadByteString(out sig);
                        break;

                    case "x5c":
                        //
                        // Array of the one attestation cert extracted from
                        // CTAP1/U2F response.
                        //
                        nextItem = ReadCertificateArray(nextItem, out x5c);
                        break;

                    default:
                        break;
                }
            }

            if (format == "none")
            {
                statement = null;
            }
            else if (format == "fido-u2f" && sig != null)
            {
                //
                // U2F attestation.
                //
                statement = new AttestationStatement(
                    FidoU2f.Algorithm,
                    sig,
                    x5c?.ToArray(),
                    true);
            }
            else if (format == "packed" &&
                Enum.IsDefined(typeof(CoseSignatureAlgorithm), (int)alg) &&
                sig != null)
            {
                //
                // CTAP2 attestation.
                //
                statement = new AttestationStatement(
                    (CoseSignatureAlgorithm)alg,
                    sig,
                    x5c?.ToArray(),
                    false);
            }
            else
            {
                throw new WebAuthnException("The attestation statement is malformed");
            }

            return nextItem;
        }

        private static CborDataItem ReadCertificateArray(
            CborDataItem dataItem,
            out ICollection<X509Certificate2> certificates)
        {
            dataItem = dataItem.ReadArrayStart(out var arrayLength);

            var certificateList = new LinkedList<X509Certificate2>();
            for (var arrayIndex = 0;
                    arrayIndex < arrayLength && !dataItem.IsBreak;
                    arrayIndex++)
            {
                dataItem = dataItem.ReadByteString(out var certificateDerData);
                certificateList.AddLast(new X509Certificate2(certificateDerData));
            }

            certificates = certificateList;
            return dataItem;
        }
    }

    public class InvalidAttestationException : Exception
    {
        public InvalidAttestationException(string message) : base(message)
        {
        }
    }
}
