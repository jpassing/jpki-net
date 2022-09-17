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
using Jpki.Format.Cbor;
using Jpki.Security.Cryptography.Cose;
using System;

namespace Jpki.Security.WebAuthn
{
    public class AttestedCredentialData
    {
        /// <summary>
        /// Credential ID.
        /// </summary>
        public CredentialId CredentialId { get; }

        /// <summary>
        /// AAGUID of the authenticator.
        /// </summary>
        public Guid Aaguid { get; }

        /// <summary>
        /// Public key.
        /// </summary>
        public CosePublicKey Key { get; }

        internal AttestedCredentialData(byte[] data, uint offset)
        {
            //
            // Format:
            // Name             Length     Description
            // ---------------- ---------- -------------------------------
            // aaguid           16         The AAGUID of the authenticator.
            // credentialIdLen  2          Byte length L of credentialId.
            // credentialId     L          Credential ID
            // publicKey        variable
            //

            var bytesRead = offset;

            bytesRead += BigEndian.ReadGuid(
                data,
                bytesRead,
                out var aaGuid);
            this.Aaguid = aaGuid;

            bytesRead += BigEndian.ReadUInt16(
                data,
                bytesRead,
                out var credentialLength);

            bytesRead += BigEndian.ReadByteArray(
                data,
                bytesRead,
                credentialLength,
                out var credentialId);
            this.CredentialId = new CredentialId(credentialId);

            this.Key = CosePublicKey.Decode(
                new CborData(
                    data,
                    (uint)bytesRead,
                    (uint)(data.Length - bytesRead)));
        }
    }
}
