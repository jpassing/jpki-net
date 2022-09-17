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
using System.Diagnostics.CodeAnalysis;
using System.Linq;

namespace Jpki.Security.WebAuthn
{
    /// <summary>
    /// Assertion, represents a successful authentication using
    /// a registered authenticator.
    /// </summary>
    public class Assertion
    {
        /// <summary>
        /// Signature over authenticator data and the client hash.
        /// </summary>
        private readonly byte[] signature;

        /// <summary>
        /// Client data used to create assertion.
        /// </summary>
        private readonly ClientData clientData;

        /// <summary>
        /// Information about the authenticator that produced
        /// the assertion.
        /// </summary>
        public AuthenticatorData AuthenticatorData { get; }

        /// <summary>
        /// User ID, only populated for resident credentials.
        /// </summary>
        public byte[]? UserId { get; }

        /// <summary>
        /// Credential that was used for authentication.
        /// </summary>
        public CredentialId CredentialId { get; }

        internal Assertion(
            ClientData clientData,
            AuthenticatorData authenticatorData,
            byte[]? userId,
            CredentialId credential,
            byte[] signature)
        {
            this.clientData = clientData.ExpectNotNull(nameof(clientData));
            this.AuthenticatorData = authenticatorData.ExpectNotNull(nameof(authenticatorData));
            this.UserId = userId;
            this.CredentialId = credential;
            this.signature = signature.ExpectNotNull(nameof(signature));
        }

        /// <summary>
        /// Verify the authenticity of the assertion against a credential's
        /// public key.
        /// </summary>
        public bool Verify(Credential credential)
        {
            if (credential.AuthenticatorData?.AttestedCredentialData == null)
            {
                throw new InvalidAttestationException(
                    "The credential does not include a key and cannot be " +
                    "used to verify an assertion");
            }

            return Verify(credential.AuthenticatorData.AttestedCredentialData.Key);
        }

        /// <summary>
        /// Verify the authenticity of the assertion against a public key.
        /// </summary>
        public bool Verify(CosePublicKey key)
        {
            var signatureBase = this.AuthenticatorData.Value
                .Concat(this.clientData.Hash)
                .ToArray();

            return key.VerifySignature(
                signatureBase,
                this.signature);
        }
    }
}
