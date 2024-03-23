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
using System.Security.Cryptography.X509Certificates;
using System.Linq;




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
    /// The metadata statement as defined in [FIDOMetadataStatement].
    /// </summary>
    public class MetadataStatement
    {
        /// <summary>
        /// The legalHeader, which must be in each Metadata Statement, is an indication of 
        /// the acceptance of the relevant legal agreement for using the MDS.
        /// </summary>
        [JsonPropertyName("legalHeader")]
        public string? LegalHeader { get; set; }

        /// <summary>
        /// The Authenticator Attestation ID. See [UAFProtocol] for the definition of the 
        /// AAID structure. 
        /// </summary>
        [JsonPropertyName("aaid")]
        public string? Aaid { get; set; }

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
        /// A human-readable, short description of the authenticator, in English.
        /// </summary>
        [JsonPropertyName("description")]
        public string? Description { get; set; }

        /// <summary>
        /// A list of human-readable short descriptions of the authenticator 
        /// in different languages, keyed by the language code. For example:
        /// 
        /// {
        ///   "ru-RU": "Пример U2F аутентификатора от FIDO Alliance", 
        ///   "fr-FR": "Exemple U2F authenticator de FIDO Alliance"
        /// }
        /// </summary>
        [JsonPropertyName("alternativeDescriptions")]
        public IDictionary<string, string>? AlternativeDescriptions { get; set; }

        /// <summary>
        /// Earliest (i.e. lowest) trustworthy authenticatorVersion meeting the 
        /// requirements specified in this metadata statement.
        /// </summary>
        [JsonPropertyName("authenticatorVersion")]
        public int AuthenticatorVersion { get; set; }

        /// <summary>
        /// The FIDO protocol family. The values "uaf", "u2f", and "fido2" are supported.
        /// </summary>
        [JsonPropertyName("protocolFamily")]
        public string? ProtocolFamily { get; set; }

        /// <summary>
        /// The Metadata Schema version.
        /// </summary>
        [JsonPropertyName("schema")]
        public int Schema { get; set; }

        /// <summary>
        /// The FIDO unified protocol version(s) (related to the specific protocol 
        /// family) supported by this authenticator.
        /// </summary>
        [JsonPropertyName("upv")]
        public IReadOnlyList<UnifiedProtocolVersion>? Upv { get; set; }

        /// <summary>
        /// The list of authentication algorithms supported by the authenticator.
        /// </summary>
        [JsonPropertyName("authenticationAlgorithms")]
        public IReadOnlyList<string>? AuthenticationAlgorithms { get; set; }

        /// <summary>
        /// The list of public key formats supported by the authenticator during 
        /// registration operations.
        /// </summary>
        [JsonPropertyName("publicKeyAlgAndEncodings")]
        public IReadOnlyList<string>? PublicKeyAlgAndEncodings { get; set; }

        /// <summary>
        /// Complete list of the supported ATTESTATION_ constant case-sensitive 
        /// string names. 
        /// </summary>
        [JsonPropertyName("attestationTypes")]
        public IReadOnlyList<string>? AttestationTypes { get; set; }

        /// <summary>
        /// A list of alternative VerificationMethodANDCombinations.
        /// 
        /// userVerificationDetails is a two dimensional array, that
        /// informs RP what VerificationMethodANDCombinations user may be 
        /// required to perform in order to pass user verification, e.g 
        /// User need to pass fingerprint, or faceprint, or password and 
        /// palm print, etc.
        /// </summary>
        [JsonPropertyName("userVerificationDetails")]
        public IReadOnlyList<IReadOnlyList<UserVerificationDescriptor>>? UserVerificationDetails { get; set; }

        /// <summary>
        /// The list of key protection types supported by the authenticator.
        /// </summary>
        [JsonPropertyName("keyProtection")]
        public IReadOnlyList<string>? KeyProtection { get; set; }

        /// <summary>
        /// This entry is set to true, if the Uauth private key is restricted by
        /// the authenticator to only sign valid FIDO signature assertions. 
        /// </summary>
        [JsonPropertyName("isKeyRestricted")]
        public bool? IsKeyRestricted { get; set; } = true;

        /// <summary>
        /// This entry is set to true, if Uauth key usage always requires a fresh user verification.
        /// </summary>
        [JsonPropertyName("isFreshUserVerificationRequired")]
        public bool? IsFreshUserVerificationRequired { get; set; } = true;

        /// <summary>
        /// The list of matcher protections supported by the authenticator. 
        /// </summary>
        [JsonPropertyName("matcherProtection")]
        public IReadOnlyList<string>? MatcherProtection { get; set; }

        /// <summary>
        /// The authenticator’s overall claimed cryptographic strength in bits 
        /// (sometimes also called security strength or security level).
        /// </summary>
        [JsonPropertyName("cryptoStrength")]
        public int CryptoStrength { get; set; }

        /// <summary>
        /// The list of supported attachment hints describing the method(s) 
        /// by which the authenticator communicates with the FIDO user device. 
        /// </summary>
        [JsonPropertyName("attachmentHint")]
        public IReadOnlyList<string>? AttachmentHint { get; set; }

        /// <summary>
        /// The list of supported transaction confirmation display capabilities. 
        /// </summary>
        [JsonPropertyName("tcDisplay")]
        public IReadOnlyList<string>? TcDisplay { get; set; }

        /// <summary>
        /// Supported MIME content type [RFC2049] for the transaction 
        /// confirmation display, such as text/plain or image/png.
        /// </summary>
        [JsonPropertyName("tcDisplayContentType")]
        public string? TcDisplayContentType { get; set; }

        /// <summary>
        /// A list of alternative DisplayPNGCharacteristicsDescriptor.
        /// </summary>
        [JsonPropertyName("tcDisplayPNGCharacteristics")]
        public IReadOnlyList<DisplayPngCharacteristicsDescriptor>? TcDisplayPNGCharacteristics { get; set; }

        [JsonPropertyName("attestationRootCertificates")]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public IReadOnlyList<string>? AttestationRootCertificateStrings { get; set; }

        /// <summary>
        /// List of attestation trust anchors for the batch chain 
        /// in the authenticator attestation. 
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public IReadOnlyList<X509Certificate2> AttestationRootCertificates 
        {
            get => this.AttestationRootCertificateStrings
                .EnsureNotNull()
                .Select(c => new X509Certificate2(Convert.FromBase64String(c)))
                .ToList();
        }

        /// <summary>
        /// A data: url [RFC2397] encoded [PNG] icon for the Authenticator.
        /// </summary>
        [JsonPropertyName("icon")]
        public string? Icon { get; set; }

        /// <summary>
        /// List of extensions supported by the authenticator.
        /// </summary>
        [JsonPropertyName("supportedExtensions")]
        public IReadOnlyList<ExtensionDescriptor>? SupportedExtensions { get; set; }

        /// <summary>
        /// Describes supported versions, extensions, AAGUID of the device and its capabilities.
        /// </summary>
        [JsonPropertyName("authenticatorGetInfo")]
        public AuthenticatorInfo? AuthenticatorGetInfo { get; set; }

        //---------------------------------------------------------------------
        // Innner classes.
        //---------------------------------------------------------------------

        /// <summary>
        /// A descriptor for a specific base user verification 
        /// method as implemented by the authenticator.
        /// </summary>
        public class UserVerificationDescriptor
        {
            public UserVerificationDescriptor()
            {
            }

            internal UserVerificationDescriptor(string userVerificationMethod)
            {
                this.UserVerificationMethod = userVerificationMethod;
            }

            [JsonPropertyName("userVerificationMethod")]
            public string? UserVerificationMethod { get; set; }

            [JsonPropertyName("caDesc")]
            public CodeAccuracyDescriptor? CodeAccuracy { get; set; }

            public override string ToString()
            {
                return this.UserVerificationMethod ?? "(null)";
            }

            public override bool Equals(object? obj)
            {
                return obj is UserVerificationDescriptor other &&
                    Equals(this.UserVerificationMethod, other.UserVerificationMethod);
            }

            public override int GetHashCode()
            {
                return this.UserVerificationMethod?.GetHashCode() ?? 0;
            }
        }

        /// <summary>
        /// Describes the relevant accuracy/complexity aspects of passcode user verification methods.
        /// </summary>
        public class CodeAccuracyDescriptor
        {
            [JsonPropertyName("base")]
            public int Base { get; set; }

            [JsonPropertyName("minLength")]
            public int MinLength { get; set; }

            [JsonPropertyName("maxRetries")]
            public int MaxRetries { get; set; }

            [JsonPropertyName("blockSlowdown")]
            public int BlockSlowdown { get; set; }
        }

        /// <summary>
        /// The unified protocol version is determined as follows:
        ///    
        /// -  in the case of FIDO UAF, use the upv value as specified in the 
        ///    respective "OperationHeader" field, see[UAFProtocol].
        ///    
        /// -  in the case of U2F, use
        ///    
        ///    major version 1, minor version 0 for U2F v1.0
        ///    major version 1, minor version 1 for U2F v1.1
        ///    major version 1, minor version 2 for U2F v1.2 also known as CTAP1
        ///    
        /// -  in the case of FIDO2/CTAP2, use
        ///    
        ///    major version 1, minor version 0 for CTAP 2.0
        ///    major version 1, minor version 1 for CTAP 2.1
        /// </summary>
        public class UnifiedProtocolVersion
        {
            [JsonPropertyName("major")]
            public int? Major { get; set; }

            [JsonPropertyName("minor")]
            public int? Minor { get; set; }

            public override string ToString()
            {
                return $"{this.Major}.{this.Minor}";
            }
        }

        /// <summary>
        /// Describes supported versions, extensions, AAGUID of the 
        /// device and its capabilities.
        /// 
        /// The information is the same reported by an authenticator 
        /// when invoking the 'authenticatorGetInfo' method, see[FIDOCTAP].
        /// </summary>
        public class AuthenticatorInfo
        {
            /// <summary>
            /// List of supported versions. Supported versions are: 
            /// 
            /// - "FIDO_2_0" for CTAP2/FIDO2/Web Authentication authenticators 
            /// - "U2F_V2" for CTAP1/U2F authenticators.
            /// </summary>
            [JsonPropertyName("versions")]
            public IReadOnlyList<string>? Versions { get; set; }

            /// <summary>
            /// List of supported extensions.
            /// </summary>
            [JsonPropertyName("extensions")]
            public IReadOnlyList<string>? Extensions { get; set; }

            [JsonPropertyName("aaguid")]
            [EditorBrowsable(EditorBrowsableState.Never)]
            public string? AaguidString { get; set; }

            /// <summary>
            /// The claimed AAGUID.
            /// </summary>
            public Guid? Aaguid
            {
                get => string.IsNullOrEmpty(this.AaguidString)
                    ? (Guid?)null
                    : Guid.Parse(this.AaguidString);
            }

            /// <summary>
            /// List of supported options.
            /// </summary>

            [JsonPropertyName("options")]
            public IDictionary<string, bool>? Options { get; set; }

            /// <summary>
            /// Maximum message size supported by the authenticator.
            /// </summary>

            [JsonPropertyName("maxMsgSize")]
            public int MaxMsgSize { get; set; }

            /// <summary>
            /// List of supported PIN Protocol versions.
            /// </summary>

            [JsonPropertyName("pinUvAuthProtocols")]
            public IReadOnlyList<int>? PinUvAuthProtocols { get; set; }
        }

        /// <summary>
        /// This descriptor contains an extension supported by the authenticator.
        /// </summary>
        public class ExtensionDescriptor
        {
            /// <summary>
            /// Identifies the extension.
            /// </summary>
            [JsonPropertyName("id")]
            public string? Id { get; set; }

            /// <summary>
            /// Indicates whether unknown extensions must be ignored (false) 
            /// or must lead to an error (true) when the extension is to be 
            /// processed by the FIDO Server, FIDO Client, ASM, or FIDO Authenticator.
            /// </summary>
            [JsonPropertyName("fail_if_unknown")]
            public bool FailIfUnknown { get; set; }

            /// <summary>
            /// Contains arbitrary data further describing the extension 
            /// and/or data needed to correctly process the extension.
            /// </summary>
            [JsonPropertyName("data")]
            public string? Data { get; set; }
        }

        /// <summary>
        /// The DisplayPNGCharacteristicsDescriptor describes a PNG image 
        /// characteristics as defined in the PNG [PNG] spec for IHDR 
        /// (image header) and PLTE (palette table)
        /// </summary>
        public class DisplayPngCharacteristicsDescriptor
        {
            /// <summary>
            /// Image width.
            /// </summary>
            [JsonPropertyName("width")]
            public int Width { get; set; }

            /// <summary>
            /// Image height.
            /// </summary>
            [JsonPropertyName("height")]
            public int Height { get; set; }

            /// <summary>
            /// Bit depth - bits per sample or per palette index.
            /// </summary>
            [JsonPropertyName("bitDepth")]
            public int BitDepth { get; set; }

            /// <summary>
            /// Color type defines the PNG image type.
            /// </summary>
            [JsonPropertyName("colorType")]
            public int ColorType { get; set; }

            /// <summary>
            /// Compression method used to compress the image data.
            /// </summary>
            [JsonPropertyName("compression")]
            public int Compression { get; set; }

            /// <summary>
            /// Filter method is the preprocessing method applied to the
            /// image data before compression.
            /// </summary>
            [JsonPropertyName("filter")]
            public int Filter { get; set; }

            /// <summary>
            /// Interlace method is the transmission order of the image data.
            /// </summary>
            [JsonPropertyName("interlace")]
            public int Interlace { get; set; }

            /// <summary>
            /// 1 to 256 palette entries
            /// </summary>
            [JsonPropertyName("plte")]
            public IReadOnlyList<RgbPaletteEntry>? Plte { get; set; }
        }

        public class RgbPaletteEntry
        {
            /// <summary>
            /// Red channel sample value.
            /// </summary>
            [JsonPropertyName("r")]
            public int R { get; set; }

            /// <summary>
            /// Green channel sample value.
            /// </summary>
            [JsonPropertyName("g")]
            public int G { get; set; }

            /// <summary>
            /// Blue channel sample value.
            /// </summary>
            [JsonPropertyName("b")]
            public int B { get; set; }

            public override string ToString()
            {
                return $"{this.R:02X}{this.G:02X}{this.B:02X}";
            }
        }
    }
}