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

using Jpki.Format.Cbor;
using Jpki.Interop;
using Jpki.Security.Cryptography.Cose;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Jpki.Security.WebAuthn.Windows
{
    public static class WindowsHello
    {
        //---------------------------------------------------------------------
        // Attestation.
        //---------------------------------------------------------------------

        private static Credential CreateCredential(
            IntPtr windowHandle,
            RelyingParty relyingParty,
            User user,
            ClientData clientData,
            AttestationOptions options,
            CancellationGuid cancellationGuid)
        {
            relyingParty.ExpectNotNull(nameof(relyingParty));
            user.ExpectNotNull(nameof(user));
            clientData.ExpectNotNull(nameof(clientData));
            options.ExpectNotNull(nameof(options));

            //
            // NB. We're only using WEBAUTHN_API_VERSION_1 features, so there's no
            // need to check the version beforehand.
            //

            if (windowHandle == IntPtr.Zero)
            {
                windowHandle = NativeMethods.GetForegroundWindow();
            }

            if (options.SignatureAlgorithms == null || options.SignatureAlgorithms.Length == 0)
            {
                throw new ArgumentException("At least one signature algorithm must be specified");
            }

            if (options.SignatureAlgorithms
                .Any(alg => alg.GetHashAlgorithm() != clientData.HashAlgorithm))
            {
                throw new ArgumentException(
                    $"One or more signature algorithms are incompatible with the " +
                    $"hash algorithm used for the client data");
            }

            var nativeRelyingParty = new NativeMethods.WEBAUTHN_RP_ENTITY_INFORMATION()
            {
                dwVersion = NativeMethods.WEBAUTHN_RP_ENTITY_INFORMATION.BaselineVersion,
                pwszId = relyingParty.Id,
                pwszName = relyingParty.Name,
                pwszIcon = relyingParty.Icon?.ToString()
            };

            var nativeCoseParameters = options.SignatureAlgorithms
                .Select(sigAlg => new NativeMethods.WEBAUTHN_COSE_CREDENTIAL_PARAMETER()
                {
                    dwVersion = NativeMethods.WEBAUTHN_COSE_CREDENTIAL_PARAMETER.BaselineVersion,
                    pwszCredentialType = NativeMethods.WEBAUTHN_CREDENTIAL_TYPE.PUBLIC_KEY,
                    lAlg = sigAlg
                }).ToArray();

            using (clientData.ToNative(out var nativeClientData))
            using (user.ToNative(out var nativeUser))
            using (Unmanaged.StructArrayToPtr(nativeCoseParameters, out var coseParametersPtr))
            {
                var nativeCoseParameterInfo = new NativeMethods.WEBAUTHN_COSE_CREDENTIAL_PARAMETERS()
                {
                    cCredentialParameters = (uint)nativeCoseParameters.Length,
                    pCredentialParameters = coseParametersPtr
                };

                var nativeOptions = new NativeMethods.WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS()
                {
                    dwVersion = NativeMethods.WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS.BaselineVersion,
                    dwTimeoutMilliseconds = (uint)options.Timeout.TotalMilliseconds,
                    CredentialList = new NativeMethods.WEBAUTHN_CREDENTIALS()
                    {
                        cCredentials = 0
                    },
                    Extensions = new NativeMethods.WEBAUTHN_EXTENSIONS()
                    {
                        cExtensions = 0
                    },

                    dwAuthenticatorAttachment = (NativeMethods.WEBAUTHN_AUTHENTICATOR_ATTACHMENT)options.Authenticator,
                    bRequireResidentKey = options.ResidentKey == ResidentKeyRequirement.Required,
                    bPreferResidentKey = options.ResidentKey == ResidentKeyRequirement.Preferred,
                    dwUserVerificationRequirement = (NativeMethods.WEBAUTHN_USER_VERIFICATION_REQUIREMENT)options.UserVerification,
                    dwAttestationConveyancePreference = (NativeMethods.WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE)options.Attestation,
                    dwFlags = 0,
                    bBrowserInPrivateMode = false,

                    pCancellationId = cancellationGuid.Handle,
                    pExcludeCredentialList = IntPtr.Zero,
                    dwEnterpriseAttestation = NativeMethods.WEBAUTHN_ENTERPRISE_ATTESTATION.NONE,
                    dwLargeBlobSupport = NativeMethods.WEBAUTHN_LARGE_BLOB_SUPPORT.NONE
                };

                var hresult = NativeMethods.WebAuthNAuthenticatorMakeCredential(
                    windowHandle,
                    ref nativeRelyingParty,
                    ref nativeUser,
                    ref nativeCoseParameterInfo,
                    ref nativeClientData,
                    ref nativeOptions,
                    out var nativeAttestationPtr);
                using (nativeAttestationPtr)
                {
                    if (hresult == HRESULT.E_CANCELLED)
                    {
                        throw new OperationCanceledException();
                    }
                    else if (hresult != HRESULT.S_OK)
                    {
                        throw WebAuthnException.FromHresult(
                            (HRESULT)hresult,
                            "WebAuthNAuthenticatorMakeCredential",
                            "Creating a new credential failed");
                    }

                    //
                    // NB. AttestationObject contains the full attestation object
                    // as defined in [WebAuthN, 5.1]. The data from the
                    // attestation object is also made available in:
                    //
                    // - pwszFormatType
                    // - pbAttestation
                    // - pbAuthenticatorData
                    //

                    var nativeAttestation = nativeAttestationPtr.ToStructure();
                    if (nativeAttestation.pbAttestation == IntPtr.Zero)
                    {
                        throw new WebAuthnException(
                            "The credential does not contain attestation data");
                    }

                    //
                    // Attestation.
                    //
                    var attestationCbor = new CborData(Unmanaged
                        .PtrToByteArray(nativeAttestation.pbAttestation, nativeAttestation.cbAttestation)
                        .AssumeNotNull());

                    AttestationStatement attestationStatement = null;
                    if (nativeAttestation.dwAttestationDecodeType == NativeMethods.WEBAUTHN_ATTESTATION_DECODE.COMMON)
                    {
                        var commonStatement = Marshal.PtrToStructure<NativeMethods.WEBAUTHN_COMMON_ATTESTATION>(
                            nativeAttestation.pvAttestationDecode);

                        if (commonStatement.pbSignature == IntPtr.Zero)
                        {
                            throw new WebAuthnException(
                                "The credential does not contain a signature");
                        }

                        var signature = Unmanaged
                            .PtrToByteArray(commonStatement.pbSignature, commonStatement.cbSignature)
                            .AssumeNotNull();

                        //
                        // NB. The first certificate is the signer, leaf certificate.
                        //
                        ICollection<X509Certificate2> certificateChain = null;
                        var x5cArray = Unmanaged.PtrToStructArray<NativeMethods.WEBAUTHN_X5C>(
                            commonStatement.pX5c,
                            commonStatement.cX5c);
                        if (x5cArray != null)
                        {
                            certificateChain = new LinkedList<X509Certificate2>();
                            for (var i = 0; i < x5cArray.Length; i++)
                            {
                                var der = Unmanaged.PtrToByteArray(x5cArray[i].pbData, x5cArray[i].cbData);
                                if (der != null)
                                {
                                    certificateChain.Add(new X509Certificate2(der));
                                }
                            }
                        }

                        var isFidoU2f = commonStatement.pwszAlg == null;

                        attestationStatement = new AttestationStatement(
                            isFidoU2f ? FidoU2f.Algorithm : commonStatement.lAlg,
                            signature,
                            certificateChain,
                            isFidoU2f);
                    }

                    //
                    // Authenticator Data.
                    //
                    if (nativeAttestation.pbAuthenticatorData == IntPtr.Zero)
                    {
                        throw new WebAuthnException(
                            "The credential does not contain authenticator data");
                    }

                    var authenticatorData = new AuthenticatorData(Unmanaged
                        .PtrToByteArray(nativeAttestation.pbAuthenticatorData, nativeAttestation.cbAuthenticatorData)
                        .AssumeNotNull());

#if DEBUG
                    using (var hash = SHA256.Create())
                    {
                        var rpIdHash = hash.ComputeHash(Encoding.UTF8.GetBytes(relyingParty.Id));
                        Debug.Assert(authenticatorData.RelyingPartyIdHash.SequenceEqual(rpIdHash));
                    }
#endif

                    //
                    // Credential ID.
                    //
                    if (nativeAttestation.pbCredentialId == IntPtr.Zero)
                    {
                        throw new WebAuthnException(
                            "The credential does not contain a credential ID");
                    }

                    var credentialId = new CredentialId(Unmanaged
                        .PtrToByteArray(nativeAttestation.pbCredentialId, nativeAttestation.cbCredentialId)
                        .AssumeNotNull());

                    var attestation = new Credential(
                        nativeAttestation.pwszFormatType,
                        clientData,
                        authenticatorData,
                        credentialId,
                        attestationStatement,
                        (Transport)nativeAttestation.dwUsedTransport);

#if DEBUG
                    if (attestation.AttestationStatement != null)
                    {
                        attestation.Verify();
                    }
#endif

                    return attestation;
                }
            }
        }

        /// <summary>
        /// Create a new credential.
        /// </summary>
        public static Task<Credential> CreateCredentialAsync(
            IntPtr windowHandle,
            RelyingParty relyingParty,
            User user,
            ClientData clientData,
            AttestationOptions options,
            CancellationToken cancellationToken)
        {
            //
            // Run on background thread so that the caller can
            // cancel the operation using the provided cancellation
            // token.
            //
            return Task.Run(() =>
            {
                using (var cancellationGuid = new CancellationGuid())
                {
                    cancellationGuid.Bind(cancellationToken);
                    return CreateCredential(
                        windowHandle,
                        relyingParty,
                        user,
                        clientData,
                        options,
                        cancellationGuid);
                }
            });
        }

        //---------------------------------------------------------------------
        // Assertion.
        //---------------------------------------------------------------------

        private static Assertion CreateAssertion(
            IntPtr windowHandle,
            RelyingParty relyingParty,
            ClientData clientData,
            AssertionOptions options,
            CancellationGuid cancellationGuid)
        {
            if (windowHandle == IntPtr.Zero)
            {
                windowHandle = NativeMethods.GetForegroundWindow();
            }

            //
            // NB. We're only using WEBAUTHN_API_VERSION_1 features, so there's no
            // need to check the version beforehand.
            //

            using (clientData.ToNative(out var nativeClientData))
            using (options.AllowedCredentials.ToNative(
                Transport.Any,
                out var allowedCredentials))
            using (Unmanaged.StructToPtr(allowedCredentials, out var allowedCredentialsPtr))
            {
                var nativeOptions = new NativeMethods.WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS()
                {
                    dwVersion = NativeMethods.WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS.BaselineVersion,
                    dwTimeoutMilliseconds = (uint)options.Timeout.TotalMilliseconds,
                    CredentialList = new NativeMethods.WEBAUTHN_CREDENTIALS()
                    {
                        cCredentials = 0,
                        pCredentials = IntPtr.Zero,
                    },
                    Extensions = new NativeMethods.WEBAUTHN_EXTENSIONS()
                    {
                        cExtensions = 0,
                        pExtensions = IntPtr.Zero
                    },
                    dwAuthenticatorAttachment = (NativeMethods.WEBAUTHN_AUTHENTICATOR_ATTACHMENT)
                        options.AuthenticatorAttachment,

                    dwUserVerificationRequirement = (NativeMethods.WEBAUTHN_USER_VERIFICATION_REQUIREMENT)
                        options.UserVerification,

                    dwFlags = 0,

                    pAllowCredentialList = allowedCredentialsPtr,
                    pCancellationId = cancellationGuid.Handle,
                };

                var hresult = NativeMethods.WebAuthNAuthenticatorGetAssertion(
                    windowHandle,
                    relyingParty.Id,
                    ref nativeClientData,
                    ref nativeOptions,
                    out var nativeAssertionPtr);
                using (nativeAssertionPtr)
                {
                    if (hresult == HRESULT.NTE_INVALID_PARAMETER)
                    {
                        throw new ArgumentException(
                            "One or more parameters are incorrect");
                    }
                    else if (hresult == HRESULT.E_CANCELLED)
                    {
                        throw new OperationCanceledException();
                    }
                    else if (hresult != HRESULT.S_OK)
                    {
                        throw WebAuthnException.FromHresult(
                            (HRESULT)hresult,
                            "WebAuthNAuthenticatorGetAssertion",
                            "Creating an assertion failed");
                    }

                    var nativeAssertion = nativeAssertionPtr.ToStructure();

                    //
                    // User ID (null for non-resident keys).
                    //
                    var userId = Unmanaged.PtrToByteArray(
                        nativeAssertion.pbUserId,
                        nativeAssertion.cbUserId);

                    //
                    // Signature (should never be null).
                    //
                    if (nativeAssertion.pbSignature == IntPtr.Zero)
                    {
                        throw new WebAuthnException(
                            "The credential does not contain a signature");
                    }

                    var signature = Unmanaged
                        .PtrToByteArray(nativeAssertion.pbSignature, nativeAssertion.cbSignature)
                        .AssumeNotNull();

                    //
                    // Signature (should never be null).
                    //
                    if (nativeAssertion.Credential.pbId == IntPtr.Zero)
                    {
                        throw new WebAuthnException(
                            "The credential does not contain a credential ID");
                    }

                    var credential = NativeConvert.FromNative(nativeAssertion.Credential);

                    //
                    // Authenticator Data (should never be null).
                    //
                    if (nativeAssertion.pbAuthenticatorData == IntPtr.Zero)
                    {
                        throw new WebAuthnException(
                            "The credential does not contain authenticator data");
                    }

                    var authenticatorData = new AuthenticatorData(Unmanaged
                        .PtrToByteArray(nativeAssertion.pbAuthenticatorData, nativeAssertion.cbAuthenticatorData)
                        .AssumeNotNull());

                    return new Assertion(
                        clientData,
                        authenticatorData,
                        userId,
                        credential,
                        signature);
                }
            }
        }

        public static Task<Assertion> CreateAssertionAsync(
            IntPtr windowHandle,
            RelyingParty relyingParty,
            ClientData clientData,
            AssertionOptions options,
            CancellationToken cancellationToken)
        {
            //
            // Run on background thread so that the caller can
            // cancel the operation using the provided cancellation
            // token.
            //
            return Task.Run(() =>
            {
                using (var cancellationGuid = new CancellationGuid())
                {
                    cancellationGuid.Bind(cancellationToken);
                    return CreateAssertion(
                        windowHandle,
                        relyingParty,
                        clientData,
                        options,
                        cancellationGuid);
                }
            });
        }

        //---------------------------------------------------------------------
        // Capabilities.
        //---------------------------------------------------------------------

        public static bool IsPlatformAuthenticatorAvailable
        {
            get
            {
                var hr = NativeMethods.WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(
                    out var available);

                if (hr != HRESULT.S_OK)
                {
                    throw WebAuthnException.FromHresult(
                        hr,
                        "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable",
                        "Determining presence of platform authenticator failed");
                }

                return available;
            }
        }

        //---------------------------------------------------------------------
        // Inner clases.
        //---------------------------------------------------------------------

        /// <summary>
        /// Options for creating credential attestations.
        /// </summary>
        public class AttestationOptions
        {
            public CoseSignatureAlgorithm[] SignatureAlgorithms { get; set; }
                = new[] { CoseSignatureAlgorithm.ES256 };

            public AuthenticatorAttachment Authenticator { get; set; }
                = AuthenticatorAttachment.CrossPlatform;

            public UserVerificationRequirement UserVerification { get; set; }
                = UserVerificationRequirement.Preferred;

            public AttestationConveyance Attestation { get; set; }
                = AttestationConveyance.None;

            public ResidentKeyRequirement ResidentKey { get; set; }

            public TimeSpan Timeout { get; set; } = TimeSpan.Zero;
        }

        /// <summary>
        /// Options for creating assertions.
        /// </summary>
        public class AssertionOptions
        {
            public ICollection<CredentialId>? AllowedCredentials { get; set; }

            public AuthenticatorAttachment AuthenticatorAttachment { get; set; }
                = AuthenticatorAttachment.Any;

            public UserVerificationRequirement UserVerification { get; set; }
                = UserVerificationRequirement.Any;

            public TimeSpan Timeout { get; set; } = TimeSpan.Zero;
        }
    }
}
