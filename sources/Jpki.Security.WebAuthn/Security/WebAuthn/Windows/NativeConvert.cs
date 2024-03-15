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

#if WINDOWS || NETFRAMEWORK

using Jpki.Interop;
using Jpki.Security.Cryptography.Cose;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace Jpki.Security.WebAuthn.Windows
{
    internal static class NativeConvert
    {
        //---------------------------------------------------------------------
        // ClientData.
        //---------------------------------------------------------------------

        internal static IDisposable ToNative(
            this ClientData clientData,
            out NativeMethods.WEBAUTHN_CLIENT_DATA native)
        {
            string hashAlgorithmId;
            switch (clientData.HashAlgorithm)
            {
                case CoseHashAlgorithm.SHA_256:
                    hashAlgorithmId = NativeMethods.WEBAUTHN_HASH_ALGORITHM.SHA_256;
                    break;

                case CoseHashAlgorithm.SHA_384:
                    hashAlgorithmId = NativeMethods.WEBAUTHN_HASH_ALGORITHM.SHA_384;
                    break;

                case CoseHashAlgorithm.SHA_512:
                    hashAlgorithmId = NativeMethods.WEBAUTHN_HASH_ALGORITHM.SHA_512;
                    break;

                default:
                    throw new ArgumentException(
                        $"Unknown hash algorithm: {clientData.HashAlgorithm}");
            }

            var disposable = Unmanaged.ByteArrayToPtr(clientData.Data, out var encodedClientDataPtr);

            native = new NativeMethods.WEBAUTHN_CLIENT_DATA()
            {
                dwVersion = NativeMethods.WEBAUTHN_CLIENT_DATA.BaselineVersion,
                cbClientDataJSON = (uint)clientData.Data.Length,
                pbClientDataJSON = encodedClientDataPtr,
                pwszHashAlgId = hashAlgorithmId
            };

            return disposable;
        }

        //---------------------------------------------------------------------
        // User.
        //---------------------------------------------------------------------

        internal static IDisposable ToNative(
            this User user,
            out NativeMethods.WEBAUTHN_USER_ENTITY_INFORMATION native)
        {
            user = user.ExpectNotNull(nameof(user));
            var disposable = Unmanaged.ByteArrayToPtr(user.Id, out var userIdentifierPtr);

            native = new NativeMethods.WEBAUTHN_USER_ENTITY_INFORMATION()
            {
                dwVersion = NativeMethods.WEBAUTHN_USER_ENTITY_INFORMATION.BaselineVersion,
                cbId = (uint)user.Id.Length,
                pbId = userIdentifierPtr,
                pwszName = user.Name,
                pwszIcon = user.Icon?.ToString(),
                pwszDisplayName = user.DisplayName
            };

            return disposable;
        }

        //---------------------------------------------------------------------
        // CredentialId.
        //---------------------------------------------------------------------

        internal static IDisposable ToNative(
            this CredentialId credentialId,
            Transport transport,
            out NativeMethods.WEBAUTHN_CREDENTIAL_EX native)
        {
            var disposable = Unmanaged.ByteArrayToPtr(credentialId.Value, out var idPtr);

            native = new NativeMethods.WEBAUTHN_CREDENTIAL_EX()
            {
                dwVersion = NativeMethods.WEBAUTHN_CREDENTIAL_EX.BaselineVersion,
                dwTransports = (WEBAUTHN_CTAP_TRANSPORT)transport,
                pwszCredentialType = NativeMethods.WEBAUTHN_CREDENTIAL_TYPE.PUBLIC_KEY,
                cbId = (uint)credentialId.Value.Length,
                pbId = idPtr
            };

            return disposable;
        }

        internal static CredentialId FromNative(NativeMethods.WEBAUTHN_CREDENTIAL_EX native)
        {
            return new CredentialId(Unmanaged
                .PtrToByteArray(native.pbId, native.cbId)
                .AssumeNotNull());
        }

        internal static CredentialId FromNative(NativeMethods.WEBAUTHN_CREDENTIAL native)
        {
            return new CredentialId(Unmanaged
                .PtrToByteArray(native.pbId, native.cbId)
                .AssumeNotNull());
        }

        //---------------------------------------------------------------------
        // CredentialList.
        //---------------------------------------------------------------------

        public static IDisposable ToNative(
            this ICollection<CredentialId>? credentialList,
            Transport transport,
            out NativeMethods.WEBAUTHN_CREDENTIAL_LIST? native)
        {
            var disposables = new LinkedList<IDisposable>();

            if (credentialList != null)
            {
                var nativeCredentialPtrs = new LinkedList<IntPtr>();
                foreach (var credential in credentialList)
                {
                    disposables.AddLast(credential.ToNative(
                        transport,
                        out var nativeCredential));

                    disposables.AddLast(Unmanaged.StructToPtr<NativeMethods.WEBAUTHN_CREDENTIAL_EX>(
                        nativeCredential,
                        out var nativeCredentialPtr));

                    nativeCredentialPtrs.AddLast(nativeCredentialPtr);
                }

                disposables.AddLast(Unmanaged.StructArrayToPtr(
                    nativeCredentialPtrs.ToArray(),
                    out var nativeCredentialsPptr));
                native = new NativeMethods.WEBAUTHN_CREDENTIAL_LIST()
                {
                    cCredentials = (uint)credentialList.Count,
                    ppCredentials = nativeCredentialsPptr
                };
            }
            else
            {
                native = null;
            }

            return Disposable.For(() =>
            {
                foreach (var disposable in disposables)
                {
                    disposable.Dispose();
                }
            });
        }

        internal static ICollection<CredentialId>? FromNative(
            NativeMethods.WEBAUTHN_CREDENTIAL_LIST? native)
        {
            if (native == null)
            {
                return null;
            }
            else
            {
                return Unmanaged
                    .PtrToStructArray<IntPtr>(native.Value.ppCredentials, native.Value.cCredentials)
                    .AssumeNotNull()
                    .Select(ptr => Marshal.PtrToStructure<NativeMethods.WEBAUTHN_CREDENTIAL_EX>(ptr))
                    .Select(nativeCred => FromNative(nativeCred))
                    .ToList();
            }
        }
    }
}

#endif