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

using Jpki.Interop;
using Jpki.Security.Cryptography.Cose;
using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace Jpki.Security.WebAuthn.Windows
{
    internal static class NativeMethods
    {
        private const string WebauthnDll = "webauthn.dll";

        /// <summary>
        /// Version of installed DLL, this determines the available
        /// capabilities.
        /// See https://github.com/microsoft/webauthn/blob/master/webauthn.h.
        /// </summary>
        internal enum WEBAUTHN_API_VERSION : uint
        {
            VERSION_1 = 1,
            VERSION_2 = 2,
            VERSION_3 = 3,
            VERSION_4 = 4,
            CURRENT_VERSION = VERSION_4
        }

        [DllImport(WebauthnDll,
            CallingConvention = CallingConvention.Winapi,
            ExactSpelling = true)]
        internal static extern WEBAUTHN_API_VERSION WebAuthNGetApiVersionNumber();

        //---------------------------------------------------------------------
        // Version 1 API set
        //---------------------------------------------------------------------

        /// <summary>
        /// Information about an RP Entity.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_RP_ENTITY_INFORMATION
        {
            public const uint BaselineVersion = 1;

            /// <summary>
            /// Version of this structure, to allow for modifications in the future.
            /// This field is required and should be set to CURRENT_VERSION above.
            /// </summary>
            public uint dwVersion;

            /// <summary>
            /// Identifier for the RP. This field is required.
            /// </summary>
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszId;

            /// <summary>
            /// Contains the friendly name of the Relying Party, such as "Acme Corporation", 
            /// "Widgets Inc" or "Awesome Site".
            /// This field is required.
            /// </summary>
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszName;

            /// <summary>
            /// Optional URL pointing to RP's logo. 
            /// </summary>
            [MarshalAs(UnmanagedType.LPWStr)]
            public string? pwszIcon;
        }

        /// <summary>
        /// Information about an User Entity
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_USER_ENTITY_INFORMATION
        {
            public const uint BaselineVersion = 1;
            public const uint MaxUserLength = 64;

            /// <summary>
            /// Version of this structure, to allow for modifications in the future.
            /// This field is required and should be set to CURRENT_VERSION above.
            /// </summary>
            public uint dwVersion;

            /// <summary>
            /// Identifier for the User. This field is required.
            /// </summary>
            public uint cbId;
            public /* PBYTE */ IntPtr pbId;

            /// <summary>
            /// Contains a detailed name for this account, such as "john.p.smith@example.com".
            /// </summary>
            [MarshalAs(UnmanagedType.LPWStr)]
            public string? pwszName;

            /// <summary>
            /// Optional URL that can be used to retrieve an image containing the 
            /// user's current avatar, or a data URI that contains the image data.
            /// </summary>
            [MarshalAs(UnmanagedType.LPWStr)]
            public string? pwszIcon;

            /// <summary>
            /// For User: Contains the friendly name associated with the user account 
            /// by the Relying Party, such as "John P. Smith".
            /// </summary>
            [MarshalAs(UnmanagedType.LPWStr)]
            public string? pwszDisplayName;
        }

        internal static class WEBAUTHN_HASH_ALGORITHM
        {
            public const string SHA_256 = "SHA-256";
            public const string SHA_384 = "SHA-384";
            public const string SHA_512 = "SHA-512";
        }

        /// <summary>
        /// Information about client data.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_CLIENT_DATA
        {
            public const uint BaselineVersion = 1;

            /// <summary>
            /// Version of this structure, to allow for modifications in the future.
            /// This field is required and should be set to CURRENT_VERSION above.
            /// </summary>
            public uint dwVersion;

            /// <summary>
            /// Size of the pbClientDataJSON field.
            /// </summary>
            public uint cbClientDataJSON;

            /// <summary>
            /// UTF-8 encoded JSON serialization of the client data.
            /// </summary>
            public /* PBYTE */ IntPtr pbClientDataJSON;

            /// <summary>
            /// Hash algorithm ID used to hash the pbClientDataJSON field.
            /// </summary>
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszHashAlgId;
        }

        internal static class WEBAUTHN_CREDENTIAL_TYPE
        {
            public const string PUBLIC_KEY = "public-key";
        }

        /// <summary>
        /// Information about credential parameters.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_COSE_CREDENTIAL_PARAMETER
        {
            public const uint BaselineVersion = 1;

            /// <summary>
            /// Version of this structure, to allow for modifications in the future.
            /// </summary>
            public uint dwVersion;

            /// <summary>
            /// Well-known credential type specifying a credential to create.
            /// </summary>
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszCredentialType;

            /// <summary>
            /// Well-known COSE algorithm specifying the algorithm to use for the credential.
            /// </summary>
            public CoseSignatureAlgorithm lAlg;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_COSE_CREDENTIAL_PARAMETERS
        {
            public uint cCredentialParameters;

            public /* PWEBAUTHN_COSE_CREDENTIAL_PARAMETER */ IntPtr pCredentialParameters;
        }

        /// <summary>
        /// Information about credential.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_CREDENTIAL
        {
            public const uint BaselineVersion = 1;

            /// <summary>
            /// Version of this structure, to allow for modifications in the future.
            /// </summary>
            public uint dwVersion;

            /// <summary>
            /// Size of pbID.
            /// </summary>
            public uint cbId;

            /// <summary>
            /// Unique ID for this particular credential.
            /// </summary>
            public IntPtr /* PBYTE */ pbId;

            /// <summary>
            /// Well-known credential type specifying what this particular credential is.
            /// </summary>
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszCredentialType;
        }


        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_CREDENTIALS
        {
            public uint cCredentials;
            public /* PWEBAUTHN_CREDENTIAL */ IntPtr pCredentials;
        }

        internal enum WEBAUTHN_CTAP_TRANSPORT : uint
        {
            USB = 0x00000001,
            NFC = 0x00000002,
            BLE = 0x00000004,
            TEST = 0x00000008,
            INTERNAL = 0x00000010,
            FLAGS_MASK = 0x0000001F,
        }

        /// <summary>
        /// Information about credential with extra information, such as, dwTransports
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_CREDENTIAL_EX
        {
            public const uint BaselineVersion = 1;

            /// <summary>
            /// Version of this structure, to allow for modifications in the future.
            /// </summary>
            public uint dwVersion;

            /// <summary>
            /// Size of pbID.
            /// </summary>
            public uint cbId;

            /// <summary>
            /// Unique ID for this particular credential.
            /// </summary>
            /// <param name=""></param>
            public /* PBYTE */ IntPtr pbId;

            /// <summary>
            /// Well-known credential type specifying what this particular credential is.
            /// </summary>
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszCredentialType;

            /// <summary>
            /// Transports. 0 implies no transport restrictions.
            /// </summary>
            public WEBAUTHN_CTAP_TRANSPORT dwTransports;
        }

        /// <summary>
        /// Information about credential list with extra information
        /// </summary>

        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_CREDENTIAL_LIST
        {
            public uint cCredentials;
            public /* PWEBAUTHN_CREDENTIAL_EX* */ IntPtr ppCredentials;
        }

        /// <summary>
        /// Information about Extensions.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_EXTENSION
        {
            public /* LPCWSTR */ IntPtr pwszExtensionIdentifier;
            public uint cbExtension;
            public /* PVOID */ IntPtr pvExtension;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_EXTENSIONS
        {
            public uint cExtensions;
            public /* PWEBAUTHN_EXTENSION */ IntPtr pExtensions;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS
        {
            public const uint BaselineVersion = 4;

            /// <summary>
            /// Version of this structure, to allow for modifications in the future.
            /// </summary>
            public uint dwVersion;

            /// <summary>
            /// Time that the operation is expected to complete within.
            /// This is used as guidance, and can be overridden by the platform.
            /// </summary>
            public uint dwTimeoutMilliseconds;

            /// <summary>
            /// Allowed Credentials List (Ignored in v4+)
            /// </summary>
            public WEBAUTHN_CREDENTIALS CredentialList;

            /// <summary>
            /// Optional extensions to parse when performing the operation.
            /// </summary>
            public WEBAUTHN_EXTENSIONS Extensions;

            /// <summary>
            /// Optional. Platform vs Cross-Platform Authenticators.
            /// </summary>
            public WEBAUTHN_AUTHENTICATOR_ATTACHMENT dwAuthenticatorAttachment;

            /// <summary>
            /// User Verification Requirement.
            /// </summary>
            public WEBAUTHN_USER_VERIFICATION_REQUIREMENT dwUserVerificationRequirement;

            /// <summary>
            /// Flags
            /// </summary>
            public uint dwFlags;

            //
            // The following fields have been added in WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_2
            //

            /// <summary>
            /// Optional identifier for the U2F AppId. Converted to UTF8 before being hashed. Not lower cased.
            /// </summary>
            public /* PCWSTR */ IntPtr pwszU2fAppId;

            /// <summary>
            /// If the following is non-NULL, then, set to TRUE if the above pwszU2fAppid was used instead of
            /// PCWSTR pwszRpId;
            /// </summary>
            public /* BOOL* */ IntPtr pbU2fAppId;

            //
            // The following fields have been added in WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_3
            //

            /// <summary>
            /// Cancellation Id - Optional - See WebAuthNGetCancellationId
            /// </summary>
            public /* GUID* */ IntPtr pCancellationId;

            //
            // The following fields have been added in WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_4
            //

            /// <summary>
            /// Allow Credential List. If present, "CredentialList" will be ignored.
            /// </summary>
            public /* PWEBAUTHN_CREDENTIAL_LIST */ IntPtr pAllowCredentialList;

            //
            // The following fields have been added in WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_5
            //

            public uint dwCredLargeBlobOperation;

            /// <summary>
            /// Size of pbCredLargeBlob
            /// </summary>
            public uint cbCredLargeBlob;

            public /* PBYTE */ IntPtr pbCredLargeBlob;

            //
            // The following fields have been added in WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6
            //

            /// <summary>
            /// PRF values which will be converted into HMAC-SECRET values according to WebAuthn Spec.
            /// </summary>
            public /* PWEBAUTHN_HMAC_SECRET_SALT_VALUES */ IntPtr pHmacSecretSaltValues;

            /// <summary>
            /// Optional. BrowserInPrivate Mode. Defaulting to FALSE.
            /// </summary>
            public bool bBrowserInPrivateMode;
        }

        internal enum WEBAUTHN_AUTHENTICATOR_ATTACHMENT : uint
        {
            ANY = 0,
            PLATFORM = 1,
            CROSS_PLATFORM = 2,
            CROSS_PLATFORM_U2F_V2 = 3,
        }

        internal enum WEBAUTHN_USER_VERIFICATION_REQUIREMENT : uint
        {
            ANY = 0,
            REQUIRED = 1,
            PREFERRED = 2,
            DISCOURAGED = 3,
        }

        internal enum WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE : uint
        {
            ANY = 0,
            NONE = 1,
            INDIRECT = 2,
            DIRECT = 3,
        }

        internal enum WEBAUTHN_ENTERPRISE_ATTESTATION : uint
        {
            NONE = 0,
            VENDOR_FACILITATED = 1,
            PLATFORM_MANAGED = 2,
        }

        internal enum WEBAUTHN_LARGE_BLOB_SUPPORT : uint
        {
            NONE = 0,
            REQUIRED = 1,
            PREFERRED = 2,
        }

        internal enum WEBAUTHN_ATTESTATION_DECODE : uint
        {
            NONE = 0,
            COMMON = 1
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS
        {
            public const uint BaselineVersion = 3;

            /// <summary>
            /// Version of this structure, to allow for modifications in the future.
            /// </summary>
            public uint dwVersion;

            /// <summary>
            /// Time that the operation is expected to complete within.
            /// This is used as guidance, and can be overridden by the platform.
            /// </summary>
            public uint dwTimeoutMilliseconds;

            /// <summary>
            /// Credentials used for exclusion.
            /// </summary>
            public WEBAUTHN_CREDENTIALS CredentialList;

            /// <summary>
            /// Optional extensions to parse when performing the operation.
            /// </summary>
            public WEBAUTHN_EXTENSIONS Extensions;

            /// <summary>
            /// Optional. Platform vs Cross-Platform Authenticators.
            /// </summary>
            public WEBAUTHN_AUTHENTICATOR_ATTACHMENT dwAuthenticatorAttachment;

            /// <summary>
            /// Optional. Require key to be resident or not. Defaulting to FALSE.
            /// </summary>
            public bool bRequireResidentKey;

            /// <summary>
            /// User Verification Requirement.
            /// </summary>
            public WEBAUTHN_USER_VERIFICATION_REQUIREMENT dwUserVerificationRequirement;

            /// <summary>
            /// Attestation Conveyance Preference.
            /// </summary>
            public WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE dwAttestationConveyancePreference;

            /// <summary>
            /// Reserved for future Use
            /// </summary>
            public uint dwFlags;

            //
            // The following fields have been added in WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_2
            //

            /// <summary>
            /// Cancellation Id - Optional - See WebAuthNGetCancellationId
            /// </summary>
            public /* GUID* */ IntPtr pCancellationId;

            //
            // The following fields have been added in WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_3
            //

            /// <summary>
            /// Exclude Credential List. If present, "CredentialList" will be ignored.
            /// </summary>
            public /* PWEBAUTHN_CREDENTIAL_LIST */ IntPtr pExcludeCredentialList;

            //
            // The following fields have been added in WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_4
            //

            /// <summary>
            /// Enterprise Attestation
            /// </summary>
            public WEBAUTHN_ENTERPRISE_ATTESTATION dwEnterpriseAttestation;

            /// <summary>
            /// Large Blob Support: none, required or preferred
            ///
            /// NTE_INVALID_PARAMETER when large blob required or preferred and
            ///   bRequireResidentKey isn't set to TRUE
            /// </summary>
            public WEBAUTHN_LARGE_BLOB_SUPPORT dwLargeBlobSupport;

            /// <summary>
            /// Optional. Prefer key to be resident. Defaulting to FALSE. When TRUE,
            /// overrides the above bRequireResidentKey.
            /// </summary>
            public bool bPreferResidentKey;

            //
            // The following fields have been added in WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_5
            //

            /// <summary>
            /// Optional. BrowserInPrivate Mode. Defaulting to FALSE.
            /// </summary>
            public bool bBrowserInPrivateMode;
        }


        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_X5C
        {
            /// <summary>
            /// Length of X.509 encoded certificate
            /// </summary>
            public uint cbData;

            /// <summary>
            /// X.509 encoded certificate bytes
            /// </summary>
            public /* PBYTE */ IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_COMMON_ATTESTATION
        {
            /// <summary>
            /// Version of this structure, to allow for modifications in the future.
            /// </summary>
            public uint dwVersion;

            /// <summary>
            /// Hash and Padding Algorithm
            /// The following won't be set for "fido-u2f" which assumes "ES256".
            /// </summary>
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszAlg;

            /// <summary>
            /// COSE algorithm.
            /// </summary>
            public CoseSignatureAlgorithm lAlg;

            /// <summary>
            /// Signature that was generated for this attestation.
            /// </summary>
            public uint cbSignature;
            public /* PBYTE */ IntPtr pbSignature;

            /// <summary>
            /// Following is set for Full Basic Attestation. If not, set then, this is 
            /// Self Attestation.
            /// 
            /// Array of X.509 DER encoded certificates. The first certificate is the 
            /// signer, leaf certificate.
            /// </summary>
            public uint cX5c;
            public /* PWEBAUTHN_X5C */ IntPtr pX5c;

            //
            // Following are also set for tpm.
            //

            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszVer; // L"2.0"
            public uint cbCertInfo;
            public /* PBYTE */ IntPtr pbCertInfo;

            public uint cbPubArea;
            public /* PBYTE */ IntPtr pbPubArea;
        }

        internal static class WEBAUTHN_ATTESTATION_TYPE
        {
            public const string PACKED = "packed";
            public const string U2F = "fido-u2f";
            public const string TPM = "tpm";
            public const string NONE = "none";
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_CREDENTIAL_ATTESTATION
        {
            /// <summary>
            /// Version of this structure, to allow for modifications in the future.
            /// </summary>
            public uint dwVersion;

            /// <summary>
            /// Attestation format type
            /// </summary>
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwszFormatType;

            /// <summary>
            /// Size of cbAuthenticatorData.
            /// </summary>
            public uint cbAuthenticatorData;

            /// <summary>
            /// Authenticator data that was created for this credential.
            /// </summary>
            public /* PBYTE */ IntPtr pbAuthenticatorData;

            /// <summary>
            ///  Size of CBOR encoded attestation information
            /// 0 => encoded as CBOR null value.
            /// </summary>
            public uint cbAttestation;

            /// <summary>
            /// Encoded CBOR attestation information
            /// </summary>
            public /* PBYTE */ IntPtr pbAttestation;

            public WEBAUTHN_ATTESTATION_DECODE dwAttestationDecodeType;

            /// <summary>
            /// Following depends on the dwAttestationDecodeType
            ///  WEBAUTHN_ATTESTATION_DECODE_NONE
            ///      NULL - not able to decode the CBOR attestation information
            ///  WEBAUTHN_ATTESTATION_DECODE_COMMON
            ///      PWEBAUTHN_COMMON_ATTESTATION;
            /// </summary>
            public IntPtr pvAttestationDecode;

            /// <summary>
            /// The CBOR encoded Attestation Object to be returned to the RP.
            /// </summary>
            public uint cbAttestationObject;
            public /* PBYTE */ IntPtr pbAttestationObject;

            /// <summary>
            /// The CredentialId bytes extracted from the Authenticator Data.
            /// Used by Edge to return to the RP.
            /// </summary>
            public uint cbCredentialId;
            public /* PBYTE */ IntPtr pbCredentialId;

            //
            // Following fields have been added in WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_2
            //

            public WEBAUTHN_EXTENSIONS Extensions;

            //
            // Following fields have been added in WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_3
            //

            /// <summary>
            /// One of the WEBAUTHN_CTAP_TRANSPORT_* bits will be set corresponding to
            /// the transport that was used.
            /// </summary>
            public WEBAUTHN_CTAP_TRANSPORT dwUsedTransport;

            //
            // Following fields have been added in WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_4
            //

            public bool bEpAtt;
            public bool bLargeBlobSupported;
            public bool bResidentKey;
        }

        internal enum WEBAUTHN_CRED_LARGE_BLOB_STATUS : uint
        {
            NONE = 0,
            SUCCESS = 1,
            NOT_SUPPORTED = 2,
            INVALID_DATA = 3,
            INVALID_PARAMETER = 4,
            NOT_FOUND = 5,
            MULTIPLE_CREDENTIALS = 6,
            LACK_OF_SPACE = 7,
            PLATFORM_ERROR = 8,
            AUTHENTICATOR_ERROR = 9,
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_HMAC_SECRET_SALT
        {
            /// <summary>
            /// Size of pbFirst.
            /// </summary>
            public uint cbFirst;
            public /* PBYTE */ IntPtr pbFirst; // Required

            /// <summary>
            /// Size of pbSecond.
            /// </summary>
            public uint cbSecond;
            public /* PBYTE */ IntPtr pbSecond;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct WEBAUTHN_ASSERTION
        {
            /// <summary>
            /// Version of this structure, to allow for modifications in the future.
            /// </summary>
            public uint dwVersion;

            /// <summary>
            /// Size of cbAuthenticatorData.
            /// </summary>
            public uint cbAuthenticatorData;

            /// <summary>
            /// Authenticator data that was created for this assertion.
            /// </summary>
            public /* PBYTE */ IntPtr pbAuthenticatorData;

            /// <summary>
            /// Size of pbSignature.
            /// </summary>
            public uint cbSignature;

            /// <summary>
            /// Signature that was generated for this assertion.
            /// </summary>
            public /* PBYTE */ IntPtr pbSignature;

            /// <summary>
            /// Credential that was used for this assertion.
            /// </summary>
            public WEBAUTHN_CREDENTIAL Credential;

            /// <summary>
            /// Size of User Id
            /// </summary>
            public uint cbUserId;

            /// <summary>
            /// UserId
            /// </summary>
            public /* PBYTE */ IntPtr pbUserId;

            //
            // Following fields have been added in WEBAUTHN_ASSERTION_VERSION_2
            //

            public WEBAUTHN_EXTENSIONS Extensions;

            /// <summary>
            /// Size of pbCredLargeBlob
            /// </summary>
            public uint cbCredLargeBlob;
            public /* PBYTE */ IntPtr pbCredLargeBlob;

            public uint dwCredLargeBlobStatus;

            //
            // Following fields have been added in WEBAUTHN_ASSERTION_VERSION_3
            //

            public /* PWEBAUTHN_HMAC_SECRET_SALT */ IntPtr pHmacSecret;
        }

        [DllImport(WebauthnDll,
            CallingConvention = CallingConvention.Winapi,
            CharSet = CharSet.Unicode,
            ExactSpelling = true)]
        internal static extern HRESULT WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(
            out bool isAvailable);

        [DllImport(WebauthnDll,
            CallingConvention = CallingConvention.Winapi,
            CharSet = CharSet.Unicode,
            ExactSpelling = true)]
        internal static extern HRESULT WebAuthNAuthenticatorMakeCredential(
            [In] IntPtr hWnd,
            [In] ref WEBAUTHN_RP_ENTITY_INFORMATION pRpInformation,
            [In] ref WEBAUTHN_USER_ENTITY_INFORMATION pUserInformation,
            [In] ref WEBAUTHN_COSE_CREDENTIAL_PARAMETERS pPubKeyCredParams,
            [In] ref WEBAUTHN_CLIENT_DATA pWebAuthNClientData,
            [In] ref WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS pWebAuthNMakeCredentialOptions,
            [Out] out CredentialAttestationSafeHandle ppWebAuthNCredentialAttestation);

        [DllImport(WebauthnDll,
            CallingConvention = CallingConvention.Winapi,
            CharSet = CharSet.Unicode,
            ExactSpelling = true)]
        internal static extern void WebAuthNFreeCredentialAttestation(
            [In] IntPtr pWebAuthNCredentialAttestation);

        [DllImport(WebauthnDll,
            CallingConvention = CallingConvention.Winapi,
            CharSet = CharSet.Unicode,
            ExactSpelling = true)]
        internal static extern HRESULT WebAuthNAuthenticatorGetAssertion(
            [In] IntPtr hWnd,
            [In][MarshalAs(UnmanagedType.LPWStr)] string relyingPartyId,
            [In] ref WEBAUTHN_CLIENT_DATA pWebAuthNClientData,
            [In] ref WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS options,
            [Out] out AssertionSafeHandle assertion);

        [DllImport(WebauthnDll,
            CallingConvention = CallingConvention.Winapi,
            CharSet = CharSet.Unicode,
            ExactSpelling = true)]
        internal static extern void WebAuthNFreeAssertion(
            [In] IntPtr pWebAuthNAssertion);

        [DllImport(WebauthnDll,
            CallingConvention = CallingConvention.Winapi,
            ExactSpelling = true)]
        internal static extern HRESULT WebAuthNGetCancellationId(
            IntPtr pCancellationId);

        [DllImport(WebauthnDll,
            CallingConvention = CallingConvention.Winapi,
            ExactSpelling = true)]
        internal static extern HRESULT WebAuthNCancelCurrentOperation(
            IntPtr pCancellationId);

        [DllImport("user32.dll")]
        internal static extern IntPtr GetForegroundWindow();

        //---------------------------------------------------------------------
        // SafeHandles.
        //---------------------------------------------------------------------

        internal class CredentialAttestationSafeHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            internal CredentialAttestationSafeHandle() : base(true)
            {
            }

            internal WEBAUTHN_CREDENTIAL_ATTESTATION ToStructure()
            {
                return Marshal.PtrToStructure<WEBAUTHN_CREDENTIAL_ATTESTATION>(this.handle);
            }

            protected override bool ReleaseHandle()
            {
                if (this.handle != IntPtr.Zero)
                {
                    WebAuthNFreeCredentialAttestation(this.handle);
                }

                return true;
            }
        }

        internal class AssertionSafeHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            internal AssertionSafeHandle() : base(true)
            {
            }

            internal WEBAUTHN_ASSERTION ToStructure()
            {
                return Marshal.PtrToStructure<WEBAUTHN_ASSERTION>(this.handle);
            }

            protected override bool ReleaseHandle()
            {
                if (this.handle != IntPtr.Zero)
                {
                    WebAuthNFreeAssertion(this.handle);
                }

                return true;
            }
        }
    }
}
