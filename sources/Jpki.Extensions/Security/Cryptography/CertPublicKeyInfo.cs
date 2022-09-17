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

#if !NET5_0_OR_GREATER

using Jpki.Interop;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Jpki.Security.Cryptography
{
    internal sealed class CertPublicKeyInfo : IDisposable
    {
        /// <summary>
        /// Handle to a CERT_PUBLIC_KEY_INFO structure.
        /// </summary>
        public LocalAllocSafeHandle Handle { get; }

        public NativeMethods.CERT_PUBLIC_KEY_INFO ToNative()
        {
            return Marshal.PtrToStructure<NativeMethods.CERT_PUBLIC_KEY_INFO>(
                this.Handle.DangerousGetHandle());
        }

        private CertPublicKeyInfo(LocalAllocSafeHandle handle)
        {
            this.Handle = handle;
        }

        //---------------------------------------------------------------------
        // CSP blob conversion.
        //---------------------------------------------------------------------

        public static CertPublicKeyInfo FromRsaCspBlob(
            uint cspBlobType,
            byte[] cspBlob)
        {
            using (Unmanaged.ByteArrayToPtr(cspBlob, out var cspBlobPtr))
            {
                //
                // Convert CSP blob to RSA Public Key DER.
                //
                if (!NativeMethods.CryptEncodeObjectEx(
                    NativeMethods.X509_ASN_ENCODING | NativeMethods.PKCS_7_ASN_ENCODING,
                    cspBlobType,
                    cspBlobPtr,
                    NativeMethods.CRYPT_DECODE_ALLOC_FLAG,
                    IntPtr.Zero,
                    out var rsaDerHandle,
                    out var rsaDerSize))
                {
                    throw new CryptographicException(
                        "The CSP blob is invalid",
                        new Win32Exception());
                }

                using (rsaDerHandle)
                {
                    //
                    // Wrap the RSA PublicKey DER blob into a CERT_PUBLIC_KEY_INFO.
                    //
                    var certKeyInfo = new NativeMethods.CERT_PUBLIC_KEY_INFO()
                    {
                        Algorithm = new NativeMethods.CRYPT_ALGORITHM_IDENTIFIER()
                        {
                            pszObjId = Oids.RSAES_PKCS1_v1_5.Value
                        },
                        PublicKey = new NativeMethods.CRYPT_BIT_BLOB()
                        {
                            pbData = rsaDerHandle.DangerousGetHandle(),
                            cbData = rsaDerSize
                        }
                    };

                    var certKeyInfoHandle = LocalAllocSafeHandle.LocalAlloc((uint)
                        Marshal.SizeOf<NativeMethods.CERT_PUBLIC_KEY_INFO>());

                    Marshal.StructureToPtr(
                        certKeyInfo,
                        certKeyInfoHandle.DangerousGetHandle(),
                        false);

                    return new CertPublicKeyInfo(certKeyInfoHandle);
                }
            }
        }

        public byte[] ToRsaCspBlob()
        {
            var nativeInfo = ToNative();

            if (nativeInfo.Algorithm.pszObjId != Oids.RSAES_PKCS1_v1_5.Value)
            {
                throw new CryptographicException("Key is not an RSA key");
            }

            //
            // Convert the RSA public key to a CSP blob.
            //
            if (!NativeMethods.CryptDecodeObjectEx(
                NativeMethods.X509_ASN_ENCODING | NativeMethods.PKCS_7_ASN_ENCODING,
                NativeMethods.RSA_CSP_PUBLICKEYBLOB,
                nativeInfo.PublicKey.pbData,
                nativeInfo.PublicKey.cbData,
                NativeMethods.CRYPT_DECODE_ALLOC_FLAG,
                IntPtr.Zero,
                out var cspKeyBlob,
                out var cspKeyBlobSize))
            {
                throw new CryptographicException(
                    "Converting the key to a CSP blob failed",
                    new Win32Exception());
            }
            else
            {
                using (cspKeyBlob)
                {
                    if (cspKeyBlob.DangerousGetHandle() == IntPtr.Zero)
                    {
                        throw new CryptographicException("CSP blob is null");
                    }

                    return Unmanaged.NonNullPtrToByteArray(
                        cspKeyBlob.DangerousGetHandle(),
                        cspKeyBlobSize);
                }
            }
        }

        //---------------------------------------------------------------------
        // CNG conversion.
        //---------------------------------------------------------------------

        public static CertPublicKeyInfo FromCngKey(CngKey cngKey, Oid formatOid)
        {
            uint certKeySize = 0;
            if (!NativeMethods.CryptExportPublicKeyInfoEx(
               cngKey.Handle,
               0,
               NativeMethods.PKCS_7_ASN_ENCODING | NativeMethods.X509_ASN_ENCODING,
               formatOid.Value,
               0,
               IntPtr.Zero,
               IntPtr.Zero,
               ref certKeySize))
            {
                throw new CryptographicException(
                    "Exporting the public key failed",
                    new Win32Exception());
            }

            var certKeyHandle = LocalAllocSafeHandle.LocalAlloc(certKeySize);

            if (NativeMethods.CryptExportPublicKeyInfoEx(
                cngKey.Handle,
                0,
                NativeMethods.PKCS_7_ASN_ENCODING | NativeMethods.X509_ASN_ENCODING,
                formatOid.Value,
                0,
                IntPtr.Zero,
                certKeyHandle.DangerousGetHandle(),
                ref certKeySize))
            {
                var certKeyInfo = new CertPublicKeyInfo(certKeyHandle);

                Debug.Assert(certKeyInfo.ToNative().Algorithm.pszObjId == formatOid.Value);

                return certKeyInfo;
            }
            else
            {
                certKeyHandle.Dispose();
                throw new CryptographicException(
                    "Exporting the public key failed",
                    new Win32Exception());
            }
        }

        //---------------------------------------------------------------------
        // DER encoding/decoding.
        //---------------------------------------------------------------------

        /// <summary>
        /// Read DER-encoded X509_PUBLIC_KEY_INFO.
        /// </summary>
        public static CertPublicKeyInfo FromDer(byte[] der, Oid formatOid)
        {
            using (Unmanaged.ByteArrayToPtr(der, out var derPtr))
            {
                if (!NativeMethods.CryptDecodeObjectEx(
                    NativeMethods.X509_ASN_ENCODING | NativeMethods.PKCS_7_ASN_ENCODING,
                    NativeMethods.X509_PUBLIC_KEY_INFO,
                    derPtr,
                    (uint)der.Length,
                    NativeMethods.CRYPT_DECODE_ALLOC_FLAG,
                    IntPtr.Zero,
                    out var certKeyInfoHandle,
                    out var certKeyInfoSize))
                {
                    throw new CryptographicException(
                        "The DER encoding is invalid",
                        new Win32Exception());
                }

                var certKeyInfo = new CertPublicKeyInfo(certKeyInfoHandle);

                if (certKeyInfo.ToNative().Algorithm.pszObjId != formatOid.Value)
                {
                    throw new CryptographicException(
                        "The public key uses an incompatible format");
                }

                return certKeyInfo;
            }
        }

        /// <summary>
        /// Encode CERT_PUBLIC_KEY_INFO as DER.
        /// </summary>
        public byte[] ToDer()
        {
            if (NativeMethods.CryptEncodeObjectEx(
                NativeMethods.X509_ASN_ENCODING | NativeMethods.PKCS_7_ASN_ENCODING,
                NativeMethods.X509_PUBLIC_KEY_INFO,
                this.Handle.DangerousGetHandle(),
                NativeMethods.CRYPT_DECODE_ALLOC_FLAG,
                IntPtr.Zero,
                out var certKeyInfoDerHandle,
                out var certKeyInfoDerSize))
            {
                using (certKeyInfoDerHandle)
                {
                    var certKeyInfoDer = new byte[certKeyInfoDerSize];
                    Marshal.Copy(
                        certKeyInfoDerHandle.DangerousGetHandle(),
                        certKeyInfoDer,
                        0,
                        (int)certKeyInfoDerSize);
                    return certKeyInfoDer;
                }
            }
            else
            {
                throw new CryptographicException(
                    "Encoding the public failed",
                    new Win32Exception());
            }
        }

        public void Dispose()
        {
            this.Handle.Dispose();
        }
    }
}

#endif