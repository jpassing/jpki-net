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
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;

namespace Jpki.Security.Cryptography
{
    /// <summary>
    /// PEM envelope for a key or certificate.
    /// </summary>
    public readonly struct PemEnvelope : IEquatable<PemEnvelope>
    {
        private static readonly string[] Header = new[]
        {
            "-----BEGIN RSA PUBLIC KEY-----",
            "-----BEGIN PUBLIC KEY-----",
            "-----BEGIN CERTIFICATE-----"
        };
        private static readonly string[] Footer = new[]
        {
            "-----END RSA PUBLIC KEY-----",
            "-----END PUBLIC KEY-----",
            "-----END CERTIFICATE-----"
        };


        /// <summary>
        /// Data format.
        /// </summary>
        public DataFormat Format { get; }

        /// <summary>
        /// DER-encoded data.
        /// </summary>
        public byte[] Data { get; }

        public PemEnvelope(DataFormat format, byte[] encodedKey)
        {
            encodedKey.ExpectNotNullOrZeroSized(nameof(encodedKey));
            format.ExpectDefined(nameof(format));

            this.Format = format;
            this.Data = encodedKey;
        }

        public static PemEnvelope Parse(string source)
        {
            source = source
                .ExpectNotNullOrEmpty(nameof(source))
                .Trim();

            //
            // Inspect header to determine format.
            //
            
            DataFormat? format = null;
            foreach (var formatCandidate in Enum.GetValues(typeof(DataFormat)))
            {
                if (source.StartsWith(Header[(int)formatCandidate]) &&
                    source.EndsWith(Footer[(int)formatCandidate]))
                {
                    format = (DataFormat)formatCandidate;
                }
            }

            if (format == null)
            {
                throw new FormatException("The key is missing a header/footer");
            }

            //
            // Decode body to get DER blob.
            //
            var der = Convert.FromBase64String(string.Concat(
                source
                    .Split('\n')
                    .Select(s => s.Trim())
                    .Where(line => !line.StartsWith("-----"))));

            return new PemEnvelope(format.Value, der);
        }

        public override string ToString()
        {
            var buffer = new StringBuilder();
            buffer.Append(Header[(int)this.Format]);
            buffer.Append("\r\n");
            buffer.Append(Convert.ToBase64String(this.Data));
            buffer.Append("\r\n");
            buffer.Append(Footer[(int)this.Format]);
            return buffer.ToString();
        }

        //---------------------------------------------------------------------
        // Equality.
        //---------------------------------------------------------------------

        public override bool Equals([NotNullWhen(true)] object? other)
        {
            return other is PemEnvelope otherEnvelope &&
                Equals(otherEnvelope);
        }

        public bool Equals(PemEnvelope other)
        {
            return
                other.Format == this.Format &&
                Enumerable.SequenceEqual(this.Data, other.Data);
        }

        public static bool operator ==(PemEnvelope left, PemEnvelope right)
        {
            return left.Equals(right);
        }

        public static bool operator !=(PemEnvelope left, PemEnvelope right)
        {
            return !(left == right);
        }

        public override int GetHashCode()
        {
            return
                this.Format.GetHashCode() ^
                this.Data.Length;
        }

        //---------------------------------------------------------------------
        // Inner classes/enums.
        //---------------------------------------------------------------------

        public enum DataFormat
        {
            /// <summary>
            /// -----BEGIN RSA PUBLIC KEY-----
            /// </summary>
            RsaPublicKey = 0,

            /// <summary>
            /// -----BEGIN PUBLIC KEY-----
            /// </summary>
            SubjectPublicKeyInfo = 1,

            /// <summary>
            /// -----BEGIN CERTIFICATE-----
            /// </summary>
            Certificate = 2
        }
    }
}
