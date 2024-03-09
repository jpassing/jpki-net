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
using System.Text;

namespace Jpki.Security.WebAuthn
{
    /// <summary>
    /// Client data, represents the contextual binding between a
    /// WebAuthn Relying Party and the client.
    /// </summary>
    public class ClientData
    {
        /// <summary>
        /// Raw data.
        /// 
        /// NB. WebAuthn works with the hash only, but the Windows
        /// API operated on the full client data.
        /// </summary>
        internal byte[] Data { get; }
        public CoseHashAlgorithm HashAlgorithm { get; }

        /// <summary>
        /// Hash, calculated from raw data.
        /// </summary>
        public byte[] Hash { get; }

        public ClientData(byte[] data, CoseHashAlgorithm hashAlgorithm)
        {
            this.Data = data.ExpectNotNull(nameof(data));
            this.HashAlgorithm = hashAlgorithm;

            var hashAlgorithmName = hashAlgorithm
                .GetName()
                .Name
                .ExpectNotNull(nameof(hashAlgorithm));

            using (var algorithm = System.Security.Cryptography.HashAlgorithm
                .Create(hashAlgorithmName)
                .ExpectNotNull(nameof(hashAlgorithm)))
            {
                this.Hash = algorithm.ComputeHash(this.Data);
            }
        }

        public static ClientData FromJson(
            string json,
            CoseHashAlgorithm hashAlgorithm = CoseHashAlgorithm.SHA_256)
        {
            json.ExpectNotNullOrEmpty(nameof(json));

            return new ClientData(
                Encoding.UTF8.GetBytes(json ?? string.Empty),
                hashAlgorithm);
        }
    }
}
