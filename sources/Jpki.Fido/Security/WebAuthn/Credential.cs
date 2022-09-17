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
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Jpki.Security.WebAuthn // Rename namespace to FidoAuth
{
    /// <summary>
    /// Attestation, represents a successful registration of an
    /// authenticator.
    /// </summary>
    public class Credential
    {
        private readonly ClientData clientData;
        private readonly string format;

        /// <summary>
        /// Credential ID (or U2F key handle) that idenfifies the
        /// public key that was issued for this attestation.
        /// </summary>
        public CredentialId Id { get; }

        /// <summary>
        /// Contextual bindings made by the authenticator.
        /// </summary>
        public AuthenticatorData AuthenticatorData { get; }

        /// <summary>
        /// Details about the public key credential itself and the 
        /// authenticator that created it. Can be null.
        /// </summary>
        public AttestationStatement? AttestationStatement { get; }

        /// <summary>
        /// Transport used to create the attestation.
        /// </summary>
        public Transport UsedTransport { get; }

        internal bool IsFidoU2F => this.format == FidoU2f.FormatIdentifier;

        internal Credential(
            string format,
            ClientData clientData,
            AuthenticatorData authenticatorData,
            CredentialId credentialId,
            AttestationStatement? attestationStatement,
            Transport usedTransport)
        {
            this.format = format;
            this.clientData = clientData.ExpectNotNull(nameof(clientData));
            this.AuthenticatorData = authenticatorData.ExpectNotNull(nameof(authenticatorData));
            this.Id = credentialId;
            this.AttestationStatement = attestationStatement;
            this.UsedTransport = usedTransport;
        }

        /// <summary>
        /// Verify that the attestation is well-formed and that the
        /// signature is valid.
        /// </summary>
        public void Verify()
        {
            if (this.AttestationStatement == null)
            {
                throw new WebAuthnException(
                    "The attestation cannot be verified because " +
                    "it lacks an attestation statement");
            }

            this.AttestationStatement.Verify(
                this.AuthenticatorData,
                this.clientData);
        }


        /// <summary>
        /// Decode attestation from CBOR.
        /// </summary>
        internal static Credential Decode(
            CborData cborData,
            ClientData clientData,
            CredentialId credential,
            Transport usedTransport)
        {
            string fmt = null;
            AttestationStatement attStmt = null;
            AuthenticatorData authData = null;

            var nextItem = cborData
                .Read()
                .ReadMapStart(out var mapLength);
            for (var mapIndex = 0;
                mapIndex < mapLength && !nextItem.IsBreak;
                mapIndex++)
            {
                nextItem = nextItem.ReadTextString(out var key);
                switch (key)
                {
                    case "fmt":
                        //
                        // Attestation statement format. 
                        //
                        nextItem = nextItem.ReadTextString(out fmt);
                        break;

                    case "attStmt":
                        //
                        // Nested attestation statement.
                        //
                        Debug.Assert(fmt != null);

                        nextItem = AttestationStatement.Decode(
                            fmt.ExpectNotNull("fmt"),
                            nextItem,
                            out attStmt);
                        break;

                    case "authData":
                        //
                        // Array of the one attestation cert extracted from
                        // CTAP1/U2F response.
                        //
                        nextItem = nextItem.ReadByteString(out var authDataRaw);
                        authData = new AuthenticatorData(authDataRaw);
                        break;

                    default:
                        break;
                }
            }

            if (fmt == null || authData == null)
            {
                throw new WebAuthnException("The attestation object is malformed");
            }

            return new Credential(
                fmt,
                clientData,
                authData,
                credential,
                attStmt,
                usedTransport);
        }
    }
}
