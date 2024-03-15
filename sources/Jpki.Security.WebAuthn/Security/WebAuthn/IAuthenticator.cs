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

    /// <summary>
    /// Options for creating credential attestations.
    /// </summary>
    public class AttestationOptions
    {
        public CoseSignatureAlgorithm[] SignatureAlgorithms { get; set; }
            = new[] { CoseSignatureAlgorithm.ES256 };

        public AuthenticatorAttachment Authenticator { get; set; }
            = AuthenticatorAttachment.CrossPlatform;

        public UserVerificationRequirement UserVerification { get; set; }
            = UserVerificationRequirement.Preferred;

        public AttestationConveyance Attestation { get; set; }
            = AttestationConveyance.None;

        public ResidentKeyRequirement ResidentKey { get; set; }

        public TimeSpan Timeout { get; set; } = TimeSpan.Zero;
    }

    /// <summary>
    /// Options for creating assertions.
    /// </summary>
    public class AssertionOptions
    {
        public ICollection<CredentialId>? AllowedCredentials { get; set; }

        public AuthenticatorAttachment AuthenticatorAttachment { get; set; }
            = AuthenticatorAttachment.Any;

        public UserVerificationRequirement UserVerification { get; set; }
            = UserVerificationRequirement.Any;

        public TimeSpan Timeout { get; set; } = TimeSpan.Zero;
    }
}
