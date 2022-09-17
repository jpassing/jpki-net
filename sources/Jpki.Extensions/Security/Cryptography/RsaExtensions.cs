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
using System;
using System.ComponentModel;
using System.Security.Cryptography;

namespace Jpki.Security.Cryptography
{
    public static class RsaExtensions
    {
        //---------------------------------------------------------------------
        // Export - .NET FW implementations for methods available in .NET.
        //---------------------------------------------------------------------

#if NET40_OR_GREATER

        private static void ImportCspBlob(
            RSA key,
            byte[] cspBlob)
        {
            if (key is RSACng)
            {
                //
                // RSACng.Key is private, so we can't import into
                // an existing key directly. But we can do so
                // indirectly.
                //
                var importedKey = CngKey.Import(cspBlob, CngKeyBlobFormat.GenericPublicBlob);
                var importedKeyParameters = new RSACng(importedKey).ExportParameters(false);
                key.ImportParameters(importedKeyParameters);
            }
            else if (key is RSACryptoServiceProvider cryptoApiKey)
            {
                cryptoApiKey.ImportCspBlob(cspBlob);
            }
            else
            {
                throw new ArgumentException("The key type is not recognized");
            }
        }

        private static byte[] ExportCspBlob(
            RSA key,
            out uint cspBlobType)
        {
            //
            // CNG and CryptoAPI use different key blob formats, and expose
            // different APIs to create them.
            //
            if (key is RSACng cngKey)
            {
                cspBlobType = NativeMethods.CNG_RSA_PUBLIC_KEY_BLOB;
                return cngKey.Key.Export(CngKeyBlobFormat.GenericPublicBlob);
            }
            else if (key is RSACryptoServiceProvider cryptoApiKey)
            {
                cspBlobType = NativeMethods.RSA_CSP_PUBLICKEYBLOB;
                return cryptoApiKey.ExportCspBlob(false);
            }
            else
            {
                throw new ArgumentException("The key type is not recognized");
            }
        }

        /// <summary>
        /// Exports the public-key portion of the current key in the X.509 
        /// SubjectPublicKeyInfo
        /// format.
        /// </summary>
        /// <returns>
        /// A byte array containing the X.509 SubjectPublicKeyInfo representation of the
        /// public-key portion of this key.
        /// </returns>
        public static byte[] ExportSubjectPublicKeyInfo(this RSA key)
        {
            var cspBlob = ExportCspBlob(key, out var cspBlobType);

            return CertPublicKeyInfo.FromRsaCspBlob(cspBlobType, cspBlob).ToDer();
        }

        /// <summary>
        /// Exports the public-key portion of the current key in the PKCS#1 RSAPublicKey
        /// format.
        /// </summary>
        /// <returns>
        /// A byte array containing the PKCS#1 RSAPublicKey representation of this key.
        /// </returns>
        public static byte[] ExportRSAPublicKey(this RSA key)
        {
            var cspBlob = ExportCspBlob(key, out var cspBlobType);

            //
            // Decode CSP blob -> RSA PublicKey DER.
            //
            using (Unmanaged.ByteArrayToPtr(cspBlob, out var cspBlobPtr))
            {
                if (NativeMethods.CryptEncodeObjectEx(
                    NativeMethods.X509_ASN_ENCODING | NativeMethods.PKCS_7_ASN_ENCODING,
                    cspBlobType,
                    cspBlobPtr,
                    NativeMethods.CRYPT_DECODE_ALLOC_FLAG,
                    IntPtr.Zero,
                    out var derBlobHandle,
                    out var derBlobSize))
                {
                    using (derBlobHandle)
                    {
                        if (derBlobHandle.DangerousGetHandle() == IntPtr.Zero)
                        {
                            throw new CryptographicException("CSP blob is null");
                        }

                        return Unmanaged.NonNullPtrToByteArray(
                            derBlobHandle.DangerousGetHandle(),
                            derBlobSize);
                    }
                }
                else
                {
                    throw new CryptographicException(
                        "Encoding the public key as CSP blob failed",
                        new Win32Exception());
                }
            }
        }

        //---------------------------------------------------------------------
        // Import - .NET FW implementations for methods available in .NET.
        //---------------------------------------------------------------------

        /// <summary>
        /// Imports the public key from a PKCS#1 RSAPublicKey structure after decryption,
        /// replacing the keys for this object.
        /// </summary>
        /// <param name="derBlob">
        /// The bytes of a PKCS#1 RSAPublicKey structure in the ASN.1-BER encoding.
        /// </param>
        /// <param name="bytesRead">
        /// When this method returns, contains a value that indicates the number of bytes
        /// read from source. This parameter is treated as uninitialized.
        /// </param>
        public static void ImportRSAPublicKey(
            this RSA key,
            byte[] derBlob,
            out int bytesRead)
        {
            using (Unmanaged.ByteArrayToPtr(derBlob, out var derBlobPtr))
            {
                //
                // Decode RSA PublicKey DER -> CSP blob.
                //
                if (NativeMethods.CryptDecodeObjectEx(
                    NativeMethods.X509_ASN_ENCODING | NativeMethods.PKCS_7_ASN_ENCODING,
                    NativeMethods.RSA_CSP_PUBLICKEYBLOB,
                    derBlobPtr,
                    (uint)derBlob.Length,
                    NativeMethods.CRYPT_DECODE_ALLOC_FLAG,
                    IntPtr.Zero,
                    out var keyBlobHandle,
                    out var keyBlobSize))
                {
                    using (keyBlobHandle)
                    {
                        if (keyBlobHandle.DangerousGetHandle() == IntPtr.Zero)
                        {
                            throw new CryptographicException("CSP blob is null");
                        }

                        var keyBlobBytes = Unmanaged.NonNullPtrToByteArray(
                            keyBlobHandle.DangerousGetHandle(),
                            keyBlobSize);

                        bytesRead = derBlob.Length;
                        ImportCspBlob(key, keyBlobBytes);
                    }
                }
                else
                {
                    throw new CryptographicException(
                        "The DER encoding is invalid",
                        new Win32Exception());
                }
            }
        }

        /// <summary>
        /// Imports the public key from an X.509 SubjectPublicKeyInfo structure 
        /// after decryption,
        /// replacing the keys for this object.
        /// </summary>
        /// <param name="certKeyInfoDer">
        /// The bytes of an X.509 SubjectPublicKeyInfo structure in the ASN.1-DER encoding.
        /// </param>
        /// <param name="bytesRead">
        /// When this method returns, contains a value that indicates the number of bytes
        /// read from source. This parameter is treated as uninitialized.
        /// </param>
        public static void ImportSubjectPublicKeyInfo(
            this RSA key,
            byte[] certKeyInfoDer,
            out int bytesRead)
        {
            using (var certPublicKeyInfo = CertPublicKeyInfo.FromDer(certKeyInfoDer, Oids.RSAES_PKCS1_v1_5))
            {
                var cspBlob = certPublicKeyInfo.ToRsaCspBlob();
                bytesRead = certKeyInfoDer.Length;
                ImportCspBlob(key, cspBlob);
            }
        }
#endif

        //---------------------------------------------------------------------
        // Convenience methods for reading/writing PEM-encoded keys.
        //---------------------------------------------------------------------

#if !NET5_0_OR_GREATER
        public static void ImportFromPem(
            this RSA key,
            string source)
        {
            ImportFromPem(key, source, out var _);
        }
#endif

        public static void ImportFromPem(
            this RSA key,
            string source,
            out PemEnvelope.DataFormat format)
        {
            var pem = PemEnvelope.Parse(source);
            format = pem.Format;

            if (format == PemEnvelope.DataFormat.RsaPublicKey)
            {
                key.ImportRSAPublicKey(pem.Data, out var _);
            }
            else
            {
                key.ImportSubjectPublicKeyInfo(pem.Data, out var _);
            }
        }

        public static string ExportToPem(
            this RSA key,
            PemEnvelope.DataFormat format)
        {
            if (format == PemEnvelope.DataFormat.RsaPublicKey)
            {
                return new PemEnvelope(format, key.ExportRSAPublicKey()).ToString();
            }
            else if (format == PemEnvelope.DataFormat.SubjectPublicKeyInfo)
            {
                return new PemEnvelope(format, key.ExportSubjectPublicKeyInfo()).ToString();
            }
            else
            {
                throw new ArgumentException("The format is not supported");
            }
        }
    }
}
