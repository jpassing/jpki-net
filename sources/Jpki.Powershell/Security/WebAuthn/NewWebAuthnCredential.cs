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

using Jpki.Powershell.Runtime;
using Jpki.Security.Cryptography.Cose;
using Jpki.Security.WebAuthn;
using System;
using System.Management.Automation;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Jpki.Powershell.Security.WebAuthn
{
    /// <summary>
    /// Create a new WebAuthn credential.
    /// </summary>
    [Cmdlet(VerbsCommon.New, "WebAuthnCredential")]
    public class NewWebAuthnCredential : AsyncCmdletBase<Credential>
    {
        private const string SimpleParameterSet = null;
        private const string DetailedParameterSet = null;

        //---------------------------------------------------------------------
        // Detailed parameter set.
        //---------------------------------------------------------------------

        [Parameter(Mandatory = true, ParameterSetName = nameof(DetailedParameterSet))]
        public RelyingParty? RelyingParty { get; set; }

        [Parameter(Mandatory = true, ParameterSetName = nameof(DetailedParameterSet))]
        public User? User { get; set; }

        [Parameter(Mandatory = true, ParameterSetName = nameof(DetailedParameterSet))]
        public ClientData? ClientData { get; set; }

        //---------------------------------------------------------------------
        // Detailed parameter set
        //---------------------------------------------------------------------

        [Parameter(Mandatory = true, ParameterSetName = nameof(SimpleParameterSet))]
        public string? RelyingPartyId { get; set; }

        [Parameter(Mandatory = true, ParameterSetName = nameof(SimpleParameterSet))]
        public string? UserId { get; set; }

        [Parameter(Mandatory = true, ParameterSetName = nameof(SimpleParameterSet))]
        public string? ClientDataJson { get; set; }

        //---------------------------------------------------------------------
        // Common parameters.
        //---------------------------------------------------------------------

        [Parameter(Mandatory = false, ParameterSetName = nameof(SimpleParameterSet))]
        [Parameter(Mandatory = false, ParameterSetName = nameof(DetailedParameterSet))]
        public CoseSignatureAlgorithm SignatureAlgorithm { get; set; }
            = CoseSignatureAlgorithm.ES256;

        [Parameter(Mandatory = false, ParameterSetName = nameof(SimpleParameterSet))]
        [Parameter(Mandatory = false, ParameterSetName = nameof(DetailedParameterSet))]
        public AuthenticatorAttachment Authenticator { get; set; }
            = AuthenticatorAttachment.CrossPlatform;

        [Parameter(Mandatory = false, ParameterSetName = nameof(SimpleParameterSet))]
        [Parameter(Mandatory = false, ParameterSetName = nameof(DetailedParameterSet))]
        public UserVerificationRequirement UserVerification { get; set; }
            = UserVerificationRequirement.Preferred;

        [Parameter(Mandatory = false, ParameterSetName = nameof(SimpleParameterSet))]
        [Parameter(Mandatory = false, ParameterSetName = nameof(DetailedParameterSet))]
        public AttestationConveyance Attestation { get; set; }
            = AttestationConveyance.None;

        [Parameter(Mandatory = false, ParameterSetName = nameof(SimpleParameterSet))]
        [Parameter(Mandatory = false, ParameterSetName = nameof(DetailedParameterSet))]
        public ResidentKeyRequirement ResidentKey { get; set; }

        protected override Task<Credential> ProcessRecordAsync(
            CancellationToken cancellationToken)
        {
            var options = new AttestationOptions()
            {
                SignatureAlgorithms = new[] { this.SignatureAlgorithm },
                Authenticator = this.Authenticator,
                UserVerification = this.UserVerification,
                Attestation = this.Attestation,
                ResidentKey = this.ResidentKey,
            };

            if (this.RelyingParty != null &&
                this.User != null &&
                this.ClientData != null)
            {
                //
                //  Detailed parameter set.
                //
                return Authenticators.WindowsHello.CreateCredentialAsync(
                    IntPtr.Zero,
                    this.RelyingParty,
                    this.User,
                    this.ClientData,
                    options,
                    cancellationToken);
            }
            else if (this.RelyingPartyId != null &&
                this.UserId != null &&
                this.ClientDataJson != null)
            {
                //
                //  Simple parameter set.
                //
                return Authenticators.WindowsHello.CreateCredentialAsync(
                    IntPtr.Zero,
                    new RelyingParty(this.RelyingPartyId, this.RelyingPartyId, null),
                    new User(Encoding.UTF8.GetBytes(this.UserId), this.UserId, null, null),
                    new ClientData(Encoding.UTF8.GetBytes(this.ClientDataJson), CoseHashAlgorithm.SHA_256),
                    options,
                    cancellationToken);
            }
            else
            {
                throw new PSArgumentException("The arguments passed to the cmdlet are invalid");
            }
        }
    }
}
