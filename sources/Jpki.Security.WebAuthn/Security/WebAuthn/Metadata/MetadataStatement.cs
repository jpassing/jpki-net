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

namespace Jpki.Security.WebAuthn.Metadata
{
    
    /// <summary>
    /// The metadata statement as defined in [FIDOMetadataStatement].
    /// </summary>
    public class MetadataStatement
    {
        [JsonConstructor]
        public MetadataStatement(
            [JsonProperty("legalHeader")] string legalHeader,
            [JsonProperty("aaguid")] string aaguid,
            [JsonProperty("description")] string description,
            [JsonProperty("authenticatorVersion")] int authenticatorVersion,
            [JsonProperty("protocolFamily")] string protocolFamily,
            [JsonProperty("schema")] int schema,
            [JsonProperty("upv")] List<UnifiedProtocolVersion> upv,
            [JsonProperty("authenticationAlgorithms")] List<string> authenticationAlgorithms,
            [JsonProperty("publicKeyAlgAndEncodings")] List<string> publicKeyAlgAndEncodings,
            [JsonProperty("attestationTypes")] List<string> attestationTypes,
            [JsonProperty("userVerificationDetails")] IReadOnlyList<IReadOnlyList<UserVerificationDetails>> userVerificationDetails,
            [JsonProperty("keyProtection")] List<string> keyProtection,
            [JsonProperty("matcherProtection")] List<string> matcherProtection,
            [JsonProperty("cryptoStrength")] int cryptoStrength,
            [JsonProperty("attachmentHint")] List<string> attachmentHint,
            [JsonProperty("tcDisplay")] List<string> tcDisplay,
            [JsonProperty("tcDisplayContentType")] string tcDisplayContentType,
            [JsonProperty("attestationRootCertificates")] List<string> attestationRootCertificates,
            [JsonProperty("icon")] string icon,
            [JsonProperty("authenticatorGetInfo")] IDictionary<string, object> authenticatorGetInfo,
            [JsonProperty("attestationCertificateKeyIdentifiers")] List<string> attestationCertificateKeyIdentifiers,
            [JsonProperty("isKeyRestricted")] bool? isKeyRestricted,
            [JsonProperty("isFreshUserVerificationRequired")] bool? isFreshUserVerificationRequired,
            [JsonProperty("aaid")] string aaid,
            [JsonProperty("supportedExtensions")] List<ExtensionDescriptor> supportedExtensions,
            [JsonProperty("alternativeDescriptions")] IDictionary<string, string> alternativeDescriptions,
            [JsonProperty("tcDisplayPNGCharacteristics")] List<DisplayPngCharacteristicsDescriptor> tcDisplayPNGCharacteristics
        )
        {
            this.LegalHeader = legalHeader;
            this.Aaguid = aaguid;
            this.Description = description;
            this.AuthenticatorVersion = authenticatorVersion;
            this.ProtocolFamily = protocolFamily;
            this.Schema = schema;
            this.Upv = upv;
            this.AuthenticationAlgorithms = authenticationAlgorithms;
            this.PublicKeyAlgAndEncodings = publicKeyAlgAndEncodings;
            this.AttestationTypes = attestationTypes;
            this.UserVerificationDetails = userVerificationDetails;
            this.KeyProtection = keyProtection;
            this.MatcherProtection = matcherProtection;
            this.CryptoStrength = cryptoStrength;
            this.AttachmentHint = attachmentHint;
            this.TcDisplay = tcDisplay;
            this.TcDisplayContentType = tcDisplayContentType;
            this.AttestationRootCertificates = attestationRootCertificates;
            this.Icon = icon;
            this.AuthenticatorGetInfo = authenticatorGetInfo;
            this.AttestationCertificateKeyIdentifiers = attestationCertificateKeyIdentifiers;
            this.IsKeyRestricted = isKeyRestricted;
            this.IsFreshUserVerificationRequired = isFreshUserVerificationRequired;
            this.Aaid = aaid;
            this.SupportedExtensions = supportedExtensions;
            this.AlternativeDescriptions = alternativeDescriptions;
            this.TcDisplayPNGCharacteristics = tcDisplayPNGCharacteristics;
        }

        /// <summary>
        /// The legalHeader, which must be in each Metadata Statement, is an indication of 
        /// the acceptance of the relevant legal agreement for using the MDS.
        /// </summary>
        [JsonProperty("legalHeader")]
        public string LegalHeader { get; }

        /// <summary>
        /// The Authenticator Attestation ID. See [UAFProtocol] for the definition of the 
        /// AAID structure. 
        /// </summary>
        [JsonProperty("aaid")]
        public string Aaid { get; }

        /// <summary>
        /// The Authenticator Attestation GUID. See [FIDOKeyAttestation] for the 
        /// definition of the AAGUID structure.
        /// </summary>
        [JsonProperty("aaguid")]
        public string Aaguid { get; }

        /// <summary>
        /// A list of the attestation certificate public key identifiers.
        /// </summary>
        [JsonProperty("attestationCertificateKeyIdentifiers")]
        public IReadOnlyList<string> AttestationCertificateKeyIdentifiers { get; }

        /// <summary>
        /// A human-readable, short description of the authenticator, in English.
        /// </summary>
        [JsonProperty("description")]
        public string Description { get; }

        /// <summary>
        /// A list of human-readable short descriptions of the authenticator 
        /// in different languages, keyed by the language code. For example:
        /// 
        /// {
        ///   "ru-RU": "Пример U2F аутентификатора от FIDO Alliance", 
        ///   "fr-FR": "Exemple U2F authenticator de FIDO Alliance"
        /// }
        /// </summary>
        [JsonProperty("alternativeDescriptions")]
        public IDictionary<string, string> AlternativeDescriptions { get; }

        /// <summary>
        /// Earliest (i.e. lowest) trustworthy authenticatorVersion meeting the 
        /// requirements specified in this metadata statement.
        /// </summary>
        [JsonProperty("authenticatorVersion")]
        public int AuthenticatorVersion { get; }

        /// <summary>
        /// The FIDO protocol family. The values "uaf", "u2f", and "fido2" are supported.
        /// </summary>
        [JsonProperty("protocolFamily")]
        public string ProtocolFamily { get; }

        /// <summary>
        /// The Metadata Schema version.
        /// </summary>
        [JsonProperty("schema")]
        public int Schema { get; }

        /// <summary>
        /// The FIDO unified protocol version(s) (related to the specific protocol 
        /// family) supported by this authenticator.
        /// </summary>
        [JsonProperty("upv")]
        public IReadOnlyList<UnifiedProtocolVersion> Upv { get; }

        /// <summary>
        /// The list of authentication algorithms supported by the authenticator.
        /// </summary>
        [JsonProperty("authenticationAlgorithms")]
        public IReadOnlyList<string> AuthenticationAlgorithms { get; }

        /// <summary>
        /// The list of public key formats supported by the authenticator during 
        /// registration operations.
        /// </summary>
        [JsonProperty("publicKeyAlgAndEncodings")]
        public IReadOnlyList<string> PublicKeyAlgAndEncodings { get; }

        /// <summary>
        /// Complete list of the supported ATTESTATION_ constant case-sensitive 
        /// string names. 
        /// </summary>
        [JsonProperty("attestationTypes")]
        public IReadOnlyList<string> AttestationTypes { get; }

        /// <summary>
        /// A list of alternative VerificationMethodANDCombinations.
        /// 
        /// userVerificationDetails is a two dimensional array, that
        /// informs RP what VerificationMethodANDCombinations user may be 
        /// required to perform in order to pass user verification, e.g 
        /// User need to pass fingerprint, or faceprint, or password and 
        /// palm print, etc.
        /// </summary>
        [JsonProperty("userVerificationDetails")]
        public IReadOnlyList<IReadOnlyList<UserVerificationDetails>> UserVerificationDetails { get; }

        /// <summary>
        /// The list of key protection types supported by the authenticator.
        /// </summary>
        [JsonProperty("keyProtection")]
        public IReadOnlyList<string> KeyProtection { get; }

        /// <summary>
        /// This entry is set to true, if the Uauth private key is restricted by
        /// the authenticator to only sign valid FIDO signature assertions. 
        /// </summary>
        [JsonProperty("isKeyRestricted")]
        public bool? IsKeyRestricted { get; } = true;

        /// <summary>
        /// This entry is set to true, if Uauth key usage always requires a fresh user verification.
        /// </summary>
        [JsonProperty("isFreshUserVerificationRequired")]
        public bool? IsFreshUserVerificationRequired { get; } = true;

        /// <summary>
        /// The list of matcher protections supported by the authenticator. 
        /// </summary>
        [JsonProperty("matcherProtection")]
        public IReadOnlyList<string> MatcherProtection { get; }

        /// <summary>
        /// The authenticator’s overall claimed cryptographic strength in bits 
        /// (sometimes also called security strength or security level).
        /// </summary>
        [JsonProperty("cryptoStrength")]
        public int CryptoStrength { get; }

        /// <summary>
        /// The list of supported attachment hints describing the method(s) 
        /// by which the authenticator communicates with the FIDO user device. 
        /// </summary>
        [JsonProperty("attachmentHint")]
        public IReadOnlyList<string> AttachmentHint { get; }

        /// <summary>
        /// The list of supported transaction confirmation display capabilities. 
        /// </summary>
        [JsonProperty("tcDisplay")]
        public IReadOnlyList<string> TcDisplay { get; }

        /// <summary>
        /// Supported MIME content type [RFC2049] for the transaction 
        /// confirmation display, such as text/plain or image/png.
        /// </summary>
        [JsonProperty("tcDisplayContentType")]
        public string TcDisplayContentType { get; }

        /// <summary>
        /// A list of alternative DisplayPNGCharacteristicsDescriptor.
        /// </summary>
        [JsonProperty("tcDisplayPNGCharacteristics")]
        public IReadOnlyList<DisplayPngCharacteristicsDescriptor> TcDisplayPNGCharacteristics { get; }

        /// <summary>
        /// List of attestation trust anchors for the batch chain 
        /// in the authenticator attestation. 
        /// </summary>
        [JsonProperty("attestationRootCertificates")]
        public IReadOnlyList<string> AttestationRootCertificates { get; } // TODO: Deserialize to Certificate2

        /// <summary>
        /// A data: url [RFC2397] encoded [PNG] icon for the Authenticator.
        /// </summary>
        [JsonProperty("icon")]
        public string Icon { get; }

        /// <summary>
        /// List of extensions supported by the authenticator.
        /// </summary>
        [JsonProperty("supportedExtensions")]
        public IReadOnlyList<ExtensionDescriptor> SupportedExtensions { get; }

        /// <summary>
        /// Describes supported versions, extensions, AAGUID of the device and its capabilities.
        /// </summary>
        [JsonProperty("authenticatorGetInfo")]
        public IDictionary<string, object> AuthenticatorGetInfo { get; }
    }

    public class UserVerificationDetails
    {
        [JsonConstructor]
        public UserVerificationDetails(
            [JsonProperty("userVerificationMethod")] string userVerificationMethod
        )
        {
            this.UserVerificationMethod = userVerificationMethod;
        }

        [JsonProperty("userVerificationMethod")]
        public string UserVerificationMethod { get; }
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
        [JsonConstructor]
        public UnifiedProtocolVersion(
            [JsonProperty("major")] int major,
            [JsonProperty("minor")] int minor
        )
        {
            this.Major = major;
            this.Minor = minor;
        }

        [JsonProperty("major")]
        public int Major { get; }

        [JsonProperty("minor")]
        public int Minor { get; }
    }

    ///// <summary>
    ///// Describes supported versions, extensions, AAGUID of the 
    ///// device and its capabilities.
    ///// 
    ///// The information is the same reported by an authenticator 
    ///// when invoking the 'authenticatorGetInfo' method, see[FIDOCTAP].
    ///// </summary>
    //public class AuthenticatorInfo
    //{
    //    [JsonConstructor]
    //    public AuthenticatorInfo(
    //        [JsonProperty("versions")] List<string> versions,
    //        [JsonProperty("extensions")] List<string> extensions,
    //        [JsonProperty("aaguid")] string aaguid,
    //        [JsonProperty("options")] Options options,
    //        [JsonProperty("maxMsgSize")] int maxMsgSize,
    //        [JsonProperty("pinUvAuthProtocols")] List<int> pinUvAuthProtocols,
    //        [JsonProperty("maxCredentialIdLength")] int? maxCredentialIdLength,
    //        [JsonProperty("transports")] List<string> transports,
    //        [JsonProperty("algorithms")] List<Algorithm> algorithms,
    //        [JsonProperty("preferredPlatformUvAttempts")] int? preferredPlatformUvAttempts,
    //        [JsonProperty("uvModality")] int? uvModality,
    //        [JsonProperty("certifications")] Certifications certifications,
    //        [JsonProperty("remainingDiscoverableCredentials")] int? remainingDiscoverableCredentials,
    //        [JsonProperty("maxCredentialCountInList")] int? maxCredentialCountInList,
    //        [JsonProperty("firmwareVersion")] int? firmwareVersion,
    //        [JsonProperty("maxSerializedLargeBlobArray")] int? maxSerializedLargeBlobArray,
    //        [JsonProperty("forcePINChange")] bool? forcePINChange,
    //        [JsonProperty("minPINLength")] int? minPINLength,
    //        [JsonProperty("maxCredBlobLength")] int? maxCredBlobLength,
    //        [JsonProperty("maxRPIDsForSetMinPINLength")] int? maxRPIDsForSetMinPINLength
    //    )
    //    {
    //        this.Versions = versions;
    //        this.Extensions = extensions;
    //        this.Aaguid = aaguid;
    //        this.Options = options;
    //        this.MaxMsgSize = maxMsgSize;
    //        this.PinUvAuthProtocols = pinUvAuthProtocols;
    //        this.MaxCredentialIdLength = maxCredentialIdLength;
    //        this.Transports = transports;
    //        this.Algorithms = algorithms;
    //        this.PreferredPlatformUvAttempts = preferredPlatformUvAttempts;
    //        this.UvModality = uvModality;
    //        this.Certifications = certifications;
    //        this.RemainingDiscoverableCredentials = remainingDiscoverableCredentials;
    //        this.MaxCredentialCountInList = maxCredentialCountInList;
    //        this.FirmwareVersion = firmwareVersion;
    //        this.MaxSerializedLargeBlobArray = maxSerializedLargeBlobArray;
    //        this.ForcePINChange = forcePINChange;
    //        this.MinPINLength = minPINLength;
    //        this.MaxCredBlobLength = maxCredBlobLength;
    //        this.MaxRPIDsForSetMinPINLength = maxRPIDsForSetMinPINLength;
    //    }

    //    /// <summary>
    //    /// List of supported versions. Supported versions are: 
    //    /// 
    //    /// - "FIDO_2_0" for CTAP2/FIDO2/Web Authentication authenticators 
    //    /// - "U2F_V2" for CTAP1/U2F authenticators.
    //    /// </summary>
    //    [JsonProperty("versions")]
    //    public IReadOnlyList<string> Versions { get; }

    //    /// <summary>
    //    /// List of supported extensions.
    //    /// </summary>
    //    [JsonProperty("extensions")]
    //    public IReadOnlyList<string> Extensions { get; }

    //    /// <summary>
    //    /// The claimed AAGUID.
    //    /// </summary>

    //    [JsonProperty("aaguid")]
    //    public string Aaguid { get; }

    //    /// <summary>
    //    /// List of supported options.
    //    /// </summary>

    //    [JsonProperty("options")]
    //    public Options Options { get; }

    //    /// <summary>
    //    /// Maximum message size supported by the authenticator.
    //    /// </summary>

    //    [JsonProperty("maxMsgSize")]
    //    public int MaxMsgSize { get; }

    //    /// <summary>
    //    /// List of supported PIN Protocol versions.
    //    /// </summary>

    //    [JsonProperty("pinUvAuthProtocols")]
    //    public IReadOnlyList<int> PinUvAuthProtocols { get; }

    //    [JsonProperty("maxCredentialIdLength")]
    //    public int? MaxCredentialIdLength { get; }

    //    [JsonProperty("transports")]
    //    public IReadOnlyList<string> Transports { get; }

    //    [JsonProperty("algorithms")]
    //    public IReadOnlyList<Algorithm> Algorithms { get; }

    //    [JsonProperty("preferredPlatformUvAttempts")]
    //    public int? PreferredPlatformUvAttempts { get; }

    //    [JsonProperty("uvModality")]
    //    public int? UvModality { get; }

    //    [JsonProperty("certifications")]
    //    public Certifications Certifications { get; }

    //    [JsonProperty("remainingDiscoverableCredentials")]
    //    public int? RemainingDiscoverableCredentials { get; }

    //    [JsonProperty("maxCredentialCountInList")]
    //    public int? MaxCredentialCountInList { get; }

    //    [JsonProperty("firmwareVersion")]
    //    public int? FirmwareVersion { get; }

    //    [JsonProperty("maxSerializedLargeBlobArray")]
    //    public int? MaxSerializedLargeBlobArray { get; }

    //    [JsonProperty("forcePINChange")]
    //    public bool? ForcePINChange { get; }

    //    [JsonProperty("minPINLength")]
    //    public int? MinPINLength { get; }

    //    [JsonProperty("maxCredBlobLength")]
    //    public int? MaxCredBlobLength { get; }

    //    [JsonProperty("maxRPIDsForSetMinPINLength")]
    //    public int? MaxRPIDsForSetMinPINLength { get; }
    //}

    /// <summary>
    /// This descriptor contains an extension supported by the authenticator.
    /// </summary>
    public class ExtensionDescriptor
    {
        [JsonConstructor]
        public ExtensionDescriptor(
            [JsonProperty("id")] string id,
            [JsonProperty("fail_if_unknown")] bool failIfUnknown,
            [JsonProperty("data")] string data
        )
        {
            this.Id = id;
            this.FailIfUnknown = failIfUnknown;
            this.Data = data;
        }

        /// <summary>
        /// Identifies the extension.
        /// </summary>
        [JsonProperty("id")]
        public string Id { get; }

        /// <summary>
        /// Indicates whether unknown extensions must be ignored (false) 
        /// or must lead to an error (true) when the extension is to be 
        /// processed by the FIDO Server, FIDO Client, ASM, or FIDO Authenticator.
        /// </summary>
        [JsonProperty("fail_if_unknown")]
        public bool FailIfUnknown { get; }

        /// <summary>
        /// Contains arbitrary data further describing the extension 
        /// and/or data needed to correctly process the extension.
        /// </summary>
        [JsonProperty("data")]
        public string Data { get; }
    }

    /// <summary>
    /// The DisplayPNGCharacteristicsDescriptor describes a PNG image 
    /// characteristics as defined in the PNG [PNG] spec for IHDR 
    /// (image header) and PLTE (palette table)
    /// </summary>
    public class DisplayPngCharacteristicsDescriptor
    {
        [JsonConstructor]
        public DisplayPngCharacteristicsDescriptor(
            [JsonProperty("width")] int width,
            [JsonProperty("height")] int height,
            [JsonProperty("bitDepth")] int bitDepth,
            [JsonProperty("colorType")] int colorType,
            [JsonProperty("compression")] int compression,
            [JsonProperty("filter")] int filter,
            [JsonProperty("interlace")] int interlace,
            [JsonProperty("plte")] List<RgbPaletteEntry> plte
        )
        {
            this.Width = width;
            this.Height = height;
            this.BitDepth = bitDepth;
            this.ColorType = colorType;
            this.Compression = compression;
            this.Filter = filter;
            this.Interlace = interlace;
            this.Plte = plte;
        }

        /// <summary>
        /// Image width.
        /// </summary>
        [JsonProperty("width")]
        public int Width { get; }

        /// <summary>
        /// Image height.
        /// </summary>
        [JsonProperty("height")]
        public int Height { get; }

        /// <summary>
        /// Bit depth - bits per sample or per palette index.
        /// </summary>
        [JsonProperty("bitDepth")]
        public int BitDepth { get; }

        /// <summary>
        /// Color type defines the PNG image type.
        /// </summary>
        [JsonProperty("colorType")]
        public int ColorType { get; }

        /// <summary>
        /// Compression method used to compress the image data.
        /// </summary>
        [JsonProperty("compression")]
        public int Compression { get; }

        /// <summary>
        /// Filter method is the preprocessing method applied to the
        /// image data before compression.
        /// </summary>
        [JsonProperty("filter")]
        public int Filter { get; }

        /// <summary>
        /// Interlace method is the transmission order of the image data.
        /// </summary>
        [JsonProperty("interlace")]
        public int Interlace { get; }

        /// <summary>
        /// 1 to 256 palette entries
        /// </summary>
        [JsonProperty("plte")]
        public IReadOnlyList<RgbPaletteEntry> Plte { get; }
    }

    public class RgbPaletteEntry
    {
        [JsonConstructor]
        public RgbPaletteEntry(
            [JsonProperty("r")] int r,
            [JsonProperty("g")] int g,
            [JsonProperty("b")] int b
        )
        {
            this.R = r;
            this.G = g;
            this.B = b;
        }

        /// <summary>
        /// Red channel sample value.
        /// </summary>
        [JsonProperty("r")]
        public int R { get; }

        /// <summary>
        /// Green channel sample value.
        /// </summary>
        [JsonProperty("g")]
        public int G { get; }

        /// <summary>
        /// Blue channel sample value.
        /// </summary>
        [JsonProperty("b")]
        public int B { get; }
    }
}
