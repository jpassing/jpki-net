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
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Jpki.Security.Cryptography
{
#if !NET5_0_OR_GREATER

    /// <summary>
    /// Specifies the data format for signatures with the DSA family of algorithms.
    /// </summary>
    public enum DSASignatureFormat
    {
        /// <summary>
        ///   The signature format from IEEE P1363, which produces a fixed size signature for a given key.
        /// </summary>
        IeeeP1363FixedFieldConcatenation,

        /// <summary>
        ///   The signature format from IETF RFC 3279, which produces a variably-sized signature.
        /// </summary>
        Rfc3279DerSequence,
    }
#endif

    public static class EcdsaExtensions
    {
#if !NET5_0_OR_GREATER

        private const DSASignatureFormat CngFormat = DSASignatureFormat.IeeeP1363FixedFieldConcatenation;

        //---------------------------------------------------------------------
        // Verify - .NET FW implementations for methods available in .NET.
        //---------------------------------------------------------------------

        public static bool VerifyData(
            this ECDsa key,
            byte[] data,
            byte[] signature,
            HashAlgorithmName hashAlgorithm,
            DSASignatureFormat signatureFormat)
        {
            return key.VerifyData(
                data,
                EcdsaSignatureFormat.Convert(
                    signature,
                    signatureFormat,
                    CngFormat,
                    (ushort)key.KeySize),
                hashAlgorithm);
        }

        public static bool VerifyData(
            this ECDsa key,
            Stream data,
            byte[] signature,
            HashAlgorithmName hashAlgorithm,
            DSASignatureFormat signatureFormat)
        {
            return key.VerifyData(
                data,
                EcdsaSignatureFormat.Convert(
                    signature,
                    signatureFormat,
                    CngFormat,
                    (ushort)key.KeySize),
                hashAlgorithm);
        }

        public static bool VerifyData(
            this ECDsa key,
            byte[] data,
            int offset,
            int count,
            byte[] signature,
            HashAlgorithmName hashAlgorithm,
            DSASignatureFormat signatureFormat)
        {
            return key.VerifyData(
                data,
                offset,
                count,
                EcdsaSignatureFormat.Convert(
                    signature,
                    signatureFormat,
                    CngFormat,
                    (ushort)key.KeySize),
                hashAlgorithm);
        }

        //---------------------------------------------------------------------
        // Sign - .NET FW implementations for methods available in .NET.
        //---------------------------------------------------------------------

        public static byte[] SignData(
            this ECDsa key,
            Stream data,
            HashAlgorithmName hashAlgorithm,
            DSASignatureFormat signatureFormat)
        {
            return EcdsaSignatureFormat.Convert(
                key.SignData(data, hashAlgorithm),
                CngFormat,
                signatureFormat,
                (ushort)key.KeySize);
        }

        public static byte[] SignData(
            this ECDsa key,
            byte[] data,
            HashAlgorithmName hashAlgorithm,
            DSASignatureFormat signatureFormat)
        {
            return EcdsaSignatureFormat.Convert(
                key.SignData(data, hashAlgorithm),
                CngFormat,
                signatureFormat,
                (ushort)key.KeySize);
        }

        public static byte[] SignData(
            this ECDsa key,
            byte[] data,
            int offset,
            int count,
            HashAlgorithmName hashAlgorithm,
            DSASignatureFormat signatureFormat)
        {
            return EcdsaSignatureFormat.Convert(
                key.SignData(data, offset, count, hashAlgorithm),
                CngFormat,
                signatureFormat,
                (ushort)key.KeySize);
        }

#endif

        //---------------------------------------------------------------------
        // Export - .NET FW implementations for methods available in .NET.
        //---------------------------------------------------------------------

#if !NET5_0_OR_GREATER

        public static byte[] ExportSubjectPublicKeyInfo(
            this ECDsa key)
        {
            var cngKey = key as ECDsaCng;
            if (cngKey == null)
            {
                throw new ArgumentException("Key is not a CNG key");
            }

            using (var certPublicKeyInfo = CertPublicKeyInfo.FromCngKey(cngKey.Key, Oids.ECC))
            {
                return certPublicKeyInfo.ToDer();
            }
        }

        public static void ImportSubjectPublicKeyInfo(
            this ECDsa key,
            byte[] certKeyInfoDer,
            out int bytesRead)
        {
            var cngKey = key as ECDsaCng;
            if (cngKey == null)
            {
                throw new ArgumentException("The key type is not recognized");
            }

            using (var certPublicKeyInfo = CertPublicKeyInfo.FromDer(certKeyInfoDer, Oids.ECC))
            {
                //
                // Import to a temporary key.
                //
                var nativeCertKeyInfo = certPublicKeyInfo.ToNative();
                if (!NativeMethods.CryptImportPublicKeyInfoEx2(
                    NativeMethods.X509_ASN_ENCODING,
                    ref nativeCertKeyInfo,
                    0,
                    IntPtr.Zero,
                    out var importedKeyHandle))
                {
                    throw new CryptographicException(
                        "Importing the public key failed",
                        new Win32Exception());
                }

                bytesRead = certKeyInfoDer.Length;

                using (importedKeyHandle)
                {
                    //
                    // Import parameters from temporary key.
                    //
                    ImportFromBcrypt(key, new BCryptKey(importedKeyHandle));
                }
            }
        }

        internal static void ImportFromBcrypt(
            this ECDsa key,
            BCryptKey bcryptKey)
        {
            if (!bcryptKey.TryGetProperty("ECCCurveName", out var curveName))
            {
                throw new ArgumentException("ECCCurveName");
            }

            var curve = ECCurve.CreateFromFriendlyName(curveName);

            //
            // Export keyBlob, which is formatted as a variable-length
            // BCRYPT_ECCKEY_BLOB structure.
            //
            var keyBlob = bcryptKey.ExportKeyBlob(CngKeyBlobFormat.EccPublicBlob.Format);
            var keySize = BitConverter.ToInt32(keyBlob, Marshal.SizeOf<uint>());

            var headerSize = 2 * Marshal.SizeOf<uint>();
            Debug.Assert(keyBlob.Length >= headerSize + 2 * keySize);

            var x = new byte[keySize];
            Array.Copy(keyBlob, headerSize, x, 0, x.Length);

            var y = new byte[keySize];
            Array.Copy(keyBlob, headerSize + keySize, y, 0, y.Length);

            key.ImportParameters(new ECParameters()
            {
                Curve = curve,
                Q = new ECPoint()
                {
                    X = x,
                    Y = y
                }
            });
        }

#endif

        //---------------------------------------------------------------------
        // Importing PEM-encoded keys.
        //---------------------------------------------------------------------

#if !(NET5_0_OR_GREATER)
        public static void ImportFromPem(
            this ECDsa key,
            string source)
        {
            var pem = PemEnvelope.Parse(source);
            if (pem.Format != PemEnvelope.DataFormat.SubjectPublicKeyInfo)
            {
                throw new FormatException("The key is not in SubjectPublicKeyInfo format");
            }

            key.ImportSubjectPublicKeyInfo(pem.Data, out var _);
        }
#endif

        //---------------------------------------------------------------------
        // Exporting PEM-encoded keys.
        //---------------------------------------------------------------------

#if !NET7_0_OR_GREATER
        public static string ExportSubjectPublicKeyInfoPem(this ECDsa key)
        {
            return new PemEnvelope(
                PemEnvelope.DataFormat.SubjectPublicKeyInfo,
                key.ExportSubjectPublicKeyInfo()).ToString();
        }
#endif
    }
}
