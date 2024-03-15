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
using System.Linq;

namespace Jpki.Security.WebAuthn
{
    /// <summary>
    /// Credential ID, a probabilistically-unique byte sequence identifying
    /// a public key credential source and its authentication assertions.
    /// </summary>
    public readonly struct CredentialId
    {
        public byte[] Value { get; }

        internal CredentialId(byte[] value)
        {
            this.Value = value.ExpectNotNull(nameof(value));
        }

        /// <summary>
        /// Return Base64 representation.
        /// </summary>
        public override string ToString()
        {
            return Convert.ToBase64String(this.Value);
        }

        /// <summary>
        /// Parse Base64 representation.
        /// </summary>
        public static CredentialId Parse(string value)
        {
            return new CredentialId(Convert.FromBase64String(value));
        }

        //---------------------------------------------------------------------
        // Equality.
        //---------------------------------------------------------------------

        public override bool Equals(object? obj)
        {
            return obj is CredentialId credential &&
                credential.Value.SequenceEqual(this.Value);
        }

        public override int GetHashCode()
        {
            return this.Value.Aggregate((a, b) => (byte)(a ^ b));
        }

        public static bool operator ==(CredentialId c1, CredentialId c2)
        {
            return c1.Equals(c2);
        }

        public static bool operator !=(CredentialId c1, CredentialId c2)
        {
            return !(c1 == c2);
        }
    }
}
