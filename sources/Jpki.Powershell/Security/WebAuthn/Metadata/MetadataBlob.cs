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

using System.Collections.Generic;
using System;
using System.ComponentModel;
using System.Linq;
using Jpki.Powershell.Runtime.Text;
using System.Text;
using System.Security.Cryptography.X509Certificates;






#if NETFRAMEWORK
using JsonPropertyName = Newtonsoft.Json.JsonPropertyAttribute;
using JsonConstructorAttribute = Newtonsoft.Json.JsonConstructorAttribute;
#else
using JsonPropertyName = System.Text.Json.Serialization.JsonPropertyNameAttribute;
using JsonConstructorAttribute = System.Text.Json.Serialization.JsonConstructorAttribute;
#endif

namespace Jpki.Security.WebAuthn.Metadata
{
    /// <summary>
    /// Describes the status of an authenticator model as identified by its 
    /// AAID/AAGUID or attestationCertificateKeyIdentifiers and potentially 
    /// some additional information
    /// </summary>
    public enum AuthenticatorStatus
    {
        Unknown = 0,

        NOT_FIDO_CERTIFIED,
        FIDO_CERTIFIED,
        USER_VERIFICATION_BYPASS,
        ATTESTATION_KEY_COMPROMISE,
        USER_KEY_REMOTE_COMPROMISE,
        USER_KEY_PHYSICAL_COMPROMISE,
        UPDATE_AVAILABLE,
        REVOKED,
        SELF_ASSERTION_SUBMITTED,
        FIDO_CERTIFIED_L1,
        FIDO_CERTIFIED_L1plus,
        FIDO_CERTIFIED_L2,
        FIDO_CERTIFIED_L2plus,
        FIDO_CERTIFIED_L3,
        FIDO_CERTIFIED_L3plus,
    };

    /// <summary>
    /// Represents the MetadataBLOBPayload.
    /// </summary>
    public class MetadataBlob
    {
        /// <summary>
        /// Parse a JWT-encoded blob without verifying the JWT.
        /// </summary>
        public static MetadataBlob ParseUntrusted(string? jwt)
        {
            var encodedBody = jwt
                .ExpectNotNull(nameof(jwt))
                .Split('.')
                .Skip(1)
                .FirstOrDefault()
                .ExpectNotNull("JWT body");

            var body = Encoding.UTF8.GetString(Base64UrlEncoding.Decode(encodedBody));
            var payload = Json.Deserialize<MetadataBlob>(body);

            return payload ?? throw new InvalidMetadataException(
                "The metadata blob does not contain a valid MetadataBLOBPayload");
        }

        /// <summary>
        /// Indication of the acceptance of the relevant legal agreement 
        /// for using the MDS.
        /// </summary>
        [JsonPropertyName("legalHeader")]
        public string? LegalHeader { get; set; }

        /// <summary>
        /// The serial number of this UAF Metadata BLOB Payload.
        /// </summary>
        [JsonPropertyName("no")]
        public int No { get; set; }

        /// <summary>
        /// Date when the next update will be provided at latest.
        /// </summary>
        [JsonPropertyName("nextUpdate")]
        public DateTimeOffset? NextUpdate { get; set; }

        /// <summary>
        /// List of zero or more MetadataBLOBPayloadEntry objects.
        /// </summary>
        [JsonPropertyName("entries")]
        public IReadOnlyList<Entry>? Entries { get; set; }

        //---------------------------------------------------------------------
        // Inner classes.
        //---------------------------------------------------------------------

        /// <summary>
        /// Status reports applicable to this authenticator.
        /// </summary>
        public class StatusReport
        {
            [JsonPropertyName("status")]
            [EditorBrowsable(EditorBrowsableState.Never)]
            public string? StatusString { get; set; }

            /// <summary>
            /// Status of the authenticator.
            /// </summary>
            public AuthenticatorStatus Status
            {
                get => string.IsNullOrEmpty(this.StatusString)
                    ? AuthenticatorStatus.Unknown
                    : (AuthenticatorStatus)Enum.Parse(
                        typeof(AuthenticatorStatus),
                        this.StatusString);
            }

            /// <summary>
            /// Date since when the status code was set, if applicable. If no date 
            /// is given, the status is assumed to be effective while present.
            /// </summary>
            [JsonPropertyName("effectiveDate")]
            public DateTimeOffset? EffectiveDate { get; set; }

            /// <summary>
            /// Version this status report relates to.
            /// </summary>
            [JsonPropertyName("authenticatorVersion")]
            public long? AuthenticatorVersion { get; set; }

            [JsonPropertyName("certificate")]
            [EditorBrowsable(EditorBrowsableState.Never)]
            public string? CertificateString { get; set; }

            /// <summary>
            /// Base64-encoded PKIX certificate value related to the current status, if applicable.
            /// </summary>
            [EditorBrowsable(EditorBrowsableState.Never)]
            public X509Certificate2? Certificate
            {
                get => this.CertificateString != null
                    ? new X509Certificate2(Convert.FromBase64String(this.CertificateString))
                    : null;
            }

            /// <summary>
            /// HTTPS URL where additional information may be found related 
            /// to the current status, if applicable.
            /// </summary>
            [JsonPropertyName("url")]
            public string? Url { get; set; }

            /// <summary>
            /// Describes the externally visible aspects of the Authenticator 
            /// certification evaluation.
            /// </summary>
            [JsonPropertyName("certificationDescriptor")]
            public string? CertificationDescriptor { get; set; }

            /// <summary>
            /// The unique identifier for the issued Certification.
            /// </summary>
            [JsonPropertyName("certificateNumber")]
            public string? CertificateNumber { get; set; }

            /// <summary>
            /// The version of the Authenticator Certification Policy 
            /// the implementation is certified to, e.g. "1.0.0".
            /// </summary>
            [JsonPropertyName("certificationPolicyVersion")]
            public string? CertificationPolicyVersion { get; set; }

            /// <summary>
            /// The document version of the Authenticator Security Requirements 
            /// the implementation is certified to, e.g. "1.2.0".
            /// </summary>
            [JsonPropertyName("certificationRequirementsVersion")]
            public string? CertificationRequirementsVersion { get; set; }
        }


        /// <summary>
        /// Represents the MetadataBLOBPayloadEntry.
        /// </summary>
        public class Entry
        {
            /// <summary>
            /// The AAID of the authenticator this metadata BLOB payload entry relates to. 
            /// See [UAFProtocol] for the definition of the AAID structure. 
            /// </summary>
            /// 
            [JsonPropertyName("aaid")]
            public string? Aaid { get; set; }

            /// <summary>
            /// The Authenticator Attestation GUID. See [FIDOKeyAttestation] for the
            /// definition of the AAGUID structure.
            /// </summary>

            [JsonPropertyName("aaguid")]
            [EditorBrowsable(EditorBrowsableState.Never)]
            public string? AaguidString { get; set; }

            /// <summary>
            /// The Authenticator Attestation GUID. See [FIDOKeyAttestation] for the 
            /// definition of the AAGUID structure.
            /// </summary>
            public Guid? Aaguid
            {
                get => string.IsNullOrEmpty(this.AaguidString)
                    ? (Guid?)null
                    : Guid.Parse(this.AaguidString);
            }

            /// <summary>
            /// A list of the attestation certificate public key identifiers.
            /// </summary>
            [JsonPropertyName("attestationCertificateKeyIdentifiers")]
            public IReadOnlyList<string>? AttestationCertificateKeyIdentifiers { get; set; }

            /// <summary>
            /// The metadata statement as defined in [FIDOMetadataStatement].
            /// </summary>
            [JsonPropertyName("metadataStatement")]
            public MetadataStatement? MetadataStatement { get; set; }

            /// <summary>
            /// Status reports applicable to this authenticator.
            /// </summary>
            [JsonPropertyName("statusReports")]
            public IReadOnlyList<StatusReport>? StatusReports { get; set; }

            /// <summary>
            /// Date since when the status report array was set to the current value.
            /// </summary>
            [JsonPropertyName("timeOfLastStatusChange")]
            public DateTimeOffset? TimeOfLastStatusChange { get; set; }
        }
    }

    public class InvalidMetadataException : Exception
    {
        internal InvalidMetadataException(string message) : base(message)
        {
        }
    }
}
