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
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Jpki.Security.WebAuthn
{
    /// <summary>
    /// WebAuthn authenticator.
    /// </summary>
    public interface IAuthenticator
    {
        /// <summary>
        /// Create a new WebAuthn credential.
        /// </summary>
        Task<Credential> CreateCredentialAsync(
            IntPtr windowHandle,
            RelyingParty relyingParty,
            User user,
            ClientData clientData,
            AttestationOptions options,
            CancellationToken cancellationToken);

        /// <summary>
        /// Create a new WebAuthn assertion.
        /// </summary>
        Task<Assertion> CreateAssertionAsync(
            IntPtr windowHandle,
            RelyingParty relyingParty,
            ClientData clientData,
            AssertionOptions options,
            CancellationToken cancellationToken);
    }

    public abstract class AuthenticatorOptions
    {

        /// <summary>
        /// Types of authenticator the user is allowed to use.
        /// </summary>
        public AuthenticatorAttachment AuthenticatorAttachment { get; set; }
            = AuthenticatorAttachment.Any;

        /// <summary>
        /// Type of verification the user is expected to perform.
        /// </summary>
        public UserVerificationRequirement UserVerification { get; set; }
            = UserVerificationRequirement.Any;

        /// <summary>
        /// Timeout allotted for authentication.
        /// </summary>
        public TimeSpan Timeout { get; set; } = TimeSpan.Zero;
    }

    /// <summary>
    /// Options for creating credential attestations.
    /// </summary>
    public class AttestationOptions : AuthenticatorOptions
    {
        /// <summary>
        /// Signature algorithms the authenticator
        /// is allowed to use.
        /// </summary>
        public CoseSignatureAlgorithm[] SignatureAlgorithms { get; set; }
            = new[] { CoseSignatureAlgorithm.ES256 };

        /// <summary>
        /// Determines whether the authenticator is expected to
        /// return an attestation.
        /// </summary>
        public AttestationConveyance Attestation { get; set; }
            = AttestationConveyance.None;

        /// <summary>
        /// Determines whether the authenticator is expected
        /// to allocate a resident key or not.
        /// </summary>
        public ResidentKeyRequirement ResidentKey { get; set; }
    }

    /// <summary>
    /// Options for creating assertions.
    /// </summary>
    public class AssertionOptions : AuthenticatorOptions
    {
        /// <summary>
        /// Set of existing credentials the authenticator can use.
        /// </summary>
        public ICollection<CredentialId>? AllowedCredentials { get; set; }
    }
}
