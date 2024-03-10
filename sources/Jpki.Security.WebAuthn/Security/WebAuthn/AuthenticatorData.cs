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

using Jpki.Format;
using System;

namespace Jpki.Security.WebAuthn
{
    /// <summary>
    /// Authenticator data, encodes contextual bindings made by the 
    /// authenticator. These bindings are controlled by the authenticator 
    /// itself, and derive their trust from the WebAuthn Relying Party's 
    /// assessment of the security properties of the authenticator.
    /// </summary>
    public class AuthenticatorData
    {
        private const int AuthenticatorDataLength = 37;

        internal byte[] Value { get; }

        /// <summary>
        /// SHA-256 hash of the RP ID the credential is scoped to.
        /// </summary>
        public byte[] RelyingPartyIdHash { get; }

        /// <summary>
        /// AuthenticatorDataFlags.
        /// </summary>
        public AuthenticatorDataFlags Flags { get; }

        /// <summary>
        /// Signature counter. The counter is incremented for each successful
        /// authenticatorGetAssertion operation and its purpose is to aid 
        /// Relying Parties in detecting cloned authenticators. 
        /// </summary>
        public uint SignCount { get; }

        /// <summary>
        /// Attested credential data. Not null if flags indicate that
        /// attested credential data was provided.
        /// </summary>
        public AttestedCredentialData? AttestedCredentialData { get; }

        internal AuthenticatorData(byte[] data)
        {
            data.ExpectNotNull(nameof(data));
            if (data.Length < AuthenticatorDataLength)
            {
                throw new ArgumentException("Authenticator data is truncated");
            }

            //
            // Format:
            // Name             Length     Description
            // ---------------- ---------- -------------------------------
            // rpIdHash         32         SHA-256 hash of the RP ID.
            // flags            1          AuthenticatorDataFlags
            // signCount        4          Signature counter.
            // attestedCredData variable
            // extensions       variable
            //
            var bytesRead = BigEndian.ReadByteArray(data, 0, 32, out var rpIdHash);
            this.RelyingPartyIdHash = rpIdHash;

            this.Flags = (AuthenticatorDataFlags)data[bytesRead++];

            bytesRead += BigEndian.ReadUInt32(data, bytesRead, out var signCount);
            this.SignCount = signCount;

            this.Value = data;

            if (this.Flags.HasFlag(AuthenticatorDataFlags.AttestedCredentialDataIncluded) &&
                bytesRead < data.Length)
            {
                this.AttestedCredentialData = new AttestedCredentialData(data, bytesRead);
            }
        }
    }

    [Flags]
    public enum AuthenticatorDataFlags : int
    {
        /// <summary>
        /// The user proved their presence using a simple form of authorization
        /// gesture, typically a touch.
        /// </summary>
        UserPresent = 1 << 0,

        /// <summary>
        /// The user was verified. In addition to a guesture (such as a touch),
        /// user verification typically requires a PIN, password, or a biometrics
        /// check.
        /// </summary>
        UserVerified = 1 << 2,
        BackupEligible = 1 << 3,
        BackedUp = 1 << 4,

        /// <summary>
        /// Authentication data includes attested credential data.
        /// </summary>
        AttestedCredentialDataIncluded = 1 << 6,

        /// <summary>
        /// Authentication data includes extensions.
        /// </summary>
        ExtensionDataIncluded = 1 << 7
    }
}
