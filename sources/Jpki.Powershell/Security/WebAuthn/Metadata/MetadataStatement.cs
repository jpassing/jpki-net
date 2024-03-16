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
        [JsonConstructor] // NB. Parameter names match attribute names.
        public MetadataStatement(
            string legalHeader,
            string aaguid,
            string description,
            int authenticatorVersion,
            string protocolFamily,
            int schema,
            List<UnifiedProtocolVersion> upv,
            List<string> authenticationAlgorithms,
            List<string> publicKeyAlgAndEncodings,
            List<string> attestationTypes,
            IReadOnlyList<IReadOnlyList<UserVerificationDetails>> userVerificationDetails,
            List<string> keyProtection,
            List<string> matcherProtection,
            int cryptoStrength,
            List<string> attachmentHint,
            List<string> tcDisplay,
            string tcDisplayContentType,
            List<string> attestationRootCertificates,
            string icon,
            IDictionary<string, object> authenticatorGetInfo,
            List<string> attestationCertificateKeyIdentifiers,
            bool? isKeyRestricted,
            bool? isFreshUserVerificationRequired,
            string aaid,
            List<ExtensionDescriptor> supportedExtensions,
            IDictionary<string, string> alternativeDescriptions,
            List<DisplayPngCharacteristicsDescriptor> tcDisplayPNGCharacteristics)
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
        [JsonPropertyName("legalHeader")]
        public string LegalHeader { get; }

        /// <summary>
        /// The Authenticator Attestation ID. See [UAFProtocol] for the definition of the 
        /// AAID structure. 
        /// </summary>
        [JsonPropertyName("aaid")]
        public string Aaid { get; }

        /// <summary>
        /// The Authenticator Attestation GUID. See [FIDOKeyAttestation] for the 
        /// definition of the AAGUID structure.
        /// </summary>
        [JsonPropertyName("aaguid")]
        public string Aaguid { get; }

        /// <summary>
        /// A list of the attestation certificate public key identifiers.
        /// </summary>
        [JsonPropertyName("attestationCertificateKeyIdentifiers")]
        public IReadOnlyList<string> AttestationCertificateKeyIdentifiers { get; }

        /// <summary>
        /// A human-readable, short description of the authenticator, in English.
        /// </summary>
        [JsonPropertyName("description")]
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
        [JsonPropertyName("alternativeDescriptions")]
        public IDictionary<string, string> AlternativeDescriptions { get; }

        /// <summary>
        /// Earliest (i.e. lowest) trustworthy authenticatorVersion meeting the 
        /// requirements specified in this metadata statement.
        /// </summary>
        [JsonPropertyName("authenticatorVersion")]
        public int AuthenticatorVersion { get; }

        /// <summary>
        /// The FIDO protocol family. The values "uaf", "u2f", and "fido2" are supported.
        /// </summary>
        [JsonPropertyName("protocolFamily")]
        public string ProtocolFamily { get; }

        /// <summary>
        /// The Metadata Schema version.
        /// </summary>
        [JsonPropertyName("schema")]
        public int Schema { get; }

        /// <summary>
        /// The FIDO unified protocol version(s) (related to the specific protocol 
        /// family) supported by this authenticator.
        /// </summary>
        [JsonPropertyName("upv")]
        public IReadOnlyList<UnifiedProtocolVersion> Upv { get; }

        /// <summary>
        /// The list of authentication algorithms supported by the authenticator.
        /// </summary>
        [JsonPropertyName("authenticationAlgorithms")]
        public IReadOnlyList<string> AuthenticationAlgorithms { get; }

        /// <summary>
        /// The list of public key formats supported by the authenticator during 
        /// registration operations.
        /// </summary>
        [JsonPropertyName("publicKeyAlgAndEncodings")]
        public IReadOnlyList<string> PublicKeyAlgAndEncodings { get; }

        /// <summary>
        /// Complete list of the supported ATTESTATION_ constant case-sensitive 
        /// string names. 
        /// </summary>
        [JsonPropertyName("attestationTypes")]
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
        [JsonPropertyName("userVerificationDetails")]
        public IReadOnlyList<IReadOnlyList<UserVerificationDetails>> UserVerificationDetails { get; }

        /// <summary>
        /// The list of key protection types supported by the authenticator.
        /// </summary>
        [JsonPropertyName("keyProtection")]
        public IReadOnlyList<string> KeyProtection { get; }

        /// <summary>
        /// This entry is set to true, if the Uauth private key is restricted by
        /// the authenticator to only sign valid FIDO signature assertions. 
        /// </summary>
        [JsonPropertyName("isKeyRestricted")]
        public bool? IsKeyRestricted { get; } = true;

        /// <summary>
        /// This entry is set to true, if Uauth key usage always requires a fresh user verification.
        /// </summary>
        [JsonPropertyName("isFreshUserVerificationRequired")]
        public bool? IsFreshUserVerificationRequired { get; } = true;

        /// <summary>
        /// The list of matcher protections supported by the authenticator. 
        /// </summary>
        [JsonPropertyName("matcherProtection")]
        public IReadOnlyList<string> MatcherProtection { get; }

        /// <summary>
        /// The authenticator’s overall claimed cryptographic strength in bits 
        /// (sometimes also called security strength or security level).
        /// </summary>
        [JsonPropertyName("cryptoStrength")]
        public int CryptoStrength { get; }

        /// <summary>
        /// The list of supported attachment hints describing the method(s) 
        /// by which the authenticator communicates with the FIDO user device. 
        /// </summary>
        [JsonPropertyName("attachmentHint")]
        public IReadOnlyList<string> AttachmentHint { get; }

        /// <summary>
        /// The list of supported transaction confirmation display capabilities. 
        /// </summary>
        [JsonPropertyName("tcDisplay")]
        public IReadOnlyList<string> TcDisplay { get; }

        /// <summary>
        /// Supported MIME content type [RFC2049] for the transaction 
        /// confirmation display, such as text/plain or image/png.
        /// </summary>
        [JsonPropertyName("tcDisplayContentType")]
        public string TcDisplayContentType { get; }

        /// <summary>
        /// A list of alternative DisplayPNGCharacteristicsDescriptor.
        /// </summary>
        [JsonPropertyName("tcDisplayPNGCharacteristics")]
        public IReadOnlyList<DisplayPngCharacteristicsDescriptor> TcDisplayPNGCharacteristics { get; }

        /// <summary>
        /// List of attestation trust anchors for the batch chain 
        /// in the authenticator attestation. 
        /// </summary>
        [JsonPropertyName("attestationRootCertificates")]
        public IReadOnlyList<string> AttestationRootCertificates { get; } // TODO: Deserialize to Certificate2

        /// <summary>
        /// A data: url [RFC2397] encoded [PNG] icon for the Authenticator.
        /// </summary>
        [JsonPropertyName("icon")]
        public string Icon { get; }

        /// <summary>
        /// List of extensions supported by the authenticator.
        /// </summary>
        [JsonPropertyName("supportedExtensions")]
        public IReadOnlyList<ExtensionDescriptor> SupportedExtensions { get; }

        /// <summary>
        /// Describes supported versions, extensions, AAGUID of the device and its capabilities.
        /// </summary>
        [JsonPropertyName("authenticatorGetInfo")]
        public IDictionary<string, object> AuthenticatorGetInfo { get; }
    }

    public class UserVerificationDetails
    {
        [JsonConstructor] // NB. Parameter names match attribute names.
        public UserVerificationDetails(
            string userVerificationMethod)
        {
            this.UserVerificationMethod = userVerificationMethod;
        }

        [JsonPropertyName("userVerificationMethod")]
        public string UserVerificationMethod { get; }

        public override string ToString()
        {
            return this.UserVerificationMethod;
        }
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
        [JsonConstructor] // NB. Parameter names match attribute names.
        public UnifiedProtocolVersion(
            int major,
            int minor)
        {
            this.Major = major;
            this.Minor = minor;
        }

        [JsonPropertyName("major")]
        public int Major { get; }

        [JsonPropertyName("minor")]
        public int Minor { get; }

        public override string ToString()
        {
            return $"{this.Major}.{this.Minor}";
        }
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
    //    [JsonConstructor] // NB. Parameter names match attribute names.
    //    public AuthenticatorInfo(
    //        List<string> versions,
    //        List<string> extensions,
    //        string aaguid,
    //        Options options,
    //        int maxMsgSize,
    //        List<int> pinUvAuthProtocols,
    //        int? maxCredentialIdLength,
    //        List<string> transports,
    //        List<Algorithm> algorithms,
    //        int? preferredPlatformUvAttempts,
    //        int? uvModality,
    //        Certifications certifications,
    //        int? remainingDiscoverableCredentials,
    //        int? maxCredentialCountInList,
    //        int? firmwareVersion,
    //        int? maxSerializedLargeBlobArray,
    //        bool? forcePINChange,
    //        int? minPINLength,
    //        int? maxCredBlobLength,
    //        int? maxRPIDsForSetMinPINLength
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
    //    [JsonPropertyName("versions")]
    //    public IReadOnlyList<string> Versions { get; }

    //    /// <summary>
    //    /// List of supported extensions.
    //    /// </summary>
    //    [JsonPropertyName("extensions")]
    //    public IReadOnlyList<string> Extensions { get; }

    //    /// <summary>
    //    /// The claimed AAGUID.
    //    /// </summary>

    //    [JsonPropertyName("aaguid")]
    //    public string Aaguid { get; }

    //    /// <summary>
    //    /// List of supported options.
    //    /// </summary>

    //    [JsonPropertyName("options")]
    //    public Options Options { get; }

    //    /// <summary>
    //    /// Maximum message size supported by the authenticator.
    //    /// </summary>

    //    [JsonPropertyName("maxMsgSize")]
    //    public int MaxMsgSize { get; }

    //    /// <summary>
    //    /// List of supported PIN Protocol versions.
    //    /// </summary>

    //    [JsonPropertyName("pinUvAuthProtocols")]
    //    public IReadOnlyList<int> PinUvAuthProtocols { get; }

    //    [JsonPropertyName("maxCredentialIdLength")]
    //    public int? MaxCredentialIdLength { get; }

    //    [JsonPropertyName("transports")]
    //    public IReadOnlyList<string> Transports { get; }

    //    [JsonPropertyName("algorithms")]
    //    public IReadOnlyList<Algorithm> Algorithms { get; }

    //    [JsonPropertyName("preferredPlatformUvAttempts")]
    //    public int? PreferredPlatformUvAttempts { get; }

    //    [JsonPropertyName("uvModality")]
    //    public int? UvModality { get; }

    //    [JsonPropertyName("certifications")]
    //    public Certifications Certifications { get; }

    //    [JsonPropertyName("remainingDiscoverableCredentials")]
    //    public int? RemainingDiscoverableCredentials { get; }

    //    [JsonPropertyName("maxCredentialCountInList")]
    //    public int? MaxCredentialCountInList { get; }

    //    [JsonPropertyName("firmwareVersion")]
    //    public int? FirmwareVersion { get; }

    //    [JsonPropertyName("maxSerializedLargeBlobArray")]
    //    public int? MaxSerializedLargeBlobArray { get; }

    //    [JsonPropertyName("forcePINChange")]
    //    public bool? ForcePINChange { get; }

    //    [JsonPropertyName("minPINLength")]
    //    public int? MinPINLength { get; }

    //    [JsonPropertyName("maxCredBlobLength")]
    //    public int? MaxCredBlobLength { get; }

    //    [JsonPropertyName("maxRPIDsForSetMinPINLength")]
    //    public int? MaxRPIDsForSetMinPINLength { get; }
    //}

    /// <summary>
    /// This descriptor contains an extension supported by the authenticator.
    /// </summary>
    public class ExtensionDescriptor
    {
        [JsonConstructor] // NB. Parameter names match attribute names.
        public ExtensionDescriptor(
            string id,
            bool failIfUnknown,
            string data)
        {
            this.Id = id;
            this.FailIfUnknown = failIfUnknown;
            this.Data = data;
        }

        /// <summary>
        /// Identifies the extension.
        /// </summary>
        [JsonPropertyName("id")]
        public string Id { get; }

        /// <summary>
        /// Indicates whether unknown extensions must be ignored (false) 
        /// or must lead to an error (true) when the extension is to be 
        /// processed by the FIDO Server, FIDO Client, ASM, or FIDO Authenticator.
        /// </summary>
        [JsonPropertyName("fail_if_unknown")]
        public bool FailIfUnknown { get; }

        /// <summary>
        /// Contains arbitrary data further describing the extension 
        /// and/or data needed to correctly process the extension.
        /// </summary>
        [JsonPropertyName("data")]
        public string Data { get; }
    }

    /// <summary>
    /// The DisplayPNGCharacteristicsDescriptor describes a PNG image 
    /// characteristics as defined in the PNG [PNG] spec for IHDR 
    /// (image header) and PLTE (palette table)
    /// </summary>
    public class DisplayPngCharacteristicsDescriptor
    {
        [JsonConstructor] // NB. Parameter names match attribute names.
        public DisplayPngCharacteristicsDescriptor(
            int width,
            int height,
            int bitDepth,
            int colorType,
            int compression,
            int filter,
            int interlace,
            List<RgbPaletteEntry> plte)
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
        [JsonPropertyName("width")]
        public int Width { get; }

        /// <summary>
        /// Image height.
        /// </summary>
        [JsonPropertyName("height")]
        public int Height { get; }

        /// <summary>
        /// Bit depth - bits per sample or per palette index.
        /// </summary>
        [JsonPropertyName("bitDepth")]
        public int BitDepth { get; }

        /// <summary>
        /// Color type defines the PNG image type.
        /// </summary>
        [JsonPropertyName("colorType")]
        public int ColorType { get; }

        /// <summary>
        /// Compression method used to compress the image data.
        /// </summary>
        [JsonPropertyName("compression")]
        public int Compression { get; }

        /// <summary>
        /// Filter method is the preprocessing method applied to the
        /// image data before compression.
        /// </summary>
        [JsonPropertyName("filter")]
        public int Filter { get; }

        /// <summary>
        /// Interlace method is the transmission order of the image data.
        /// </summary>
        [JsonPropertyName("interlace")]
        public int Interlace { get; }

        /// <summary>
        /// 1 to 256 palette entries
        /// </summary>
        [JsonPropertyName("plte")]
        public IReadOnlyList<RgbPaletteEntry> Plte { get; }
    }

    public class RgbPaletteEntry
    {
        [JsonConstructor] // NB. Parameter names match attribute names.
        public RgbPaletteEntry(
            int r,
            int g,
            int b)
        {
            this.R = r;
            this.G = g;
            this.B = b;
        }

        /// <summary>
        /// Red channel sample value.
        /// </summary>
        [JsonPropertyName("r")]
        public int R { get; }

        /// <summary>
        /// Green channel sample value.
        /// </summary>
        [JsonPropertyName("g")]
        public int G { get; }

        /// <summary>
        /// Blue channel sample value.
        /// </summary>
        [JsonPropertyName("b")]
        public int B { get; }

        public override string ToString()
        {
            return $"{this.R:02X}{this.G:02X}{this.B:02X}";
        }
    }
}
