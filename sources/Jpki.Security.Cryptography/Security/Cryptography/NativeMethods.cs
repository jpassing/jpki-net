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
using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;

namespace Jpki.Security.Cryptography
{
#if NET40_OR_GREATER

    internal class NativeMethods
    {
        public const uint X509_ASN_ENCODING = 0x1;
        public const uint PKCS_7_ASN_ENCODING = 0x10000;
        public const uint CRYPT_DECODE_ALLOC_FLAG = 0x8000;

        //
        // Constants for CryptEncodeObject and CryptDecodeObject.
        // 
        // https://docs.microsoft.com/en-us/windows/win32/seccrypto/constants-for-cryptencodeobject-and-cryptdecodeobject
        //
        public const uint X509_PUBLIC_KEY_INFO = 8;
        public const uint RSA_CSP_PUBLICKEYBLOB = 19;
        public const uint CNG_RSA_PUBLIC_KEY_BLOB = 72;

        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPT_ALGORITHM_IDENTIFIER
        {
            [MarshalAs(UnmanagedType.LPStr)] public string pszObjId;
            public int cbData;
            public IntPtr pbData;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CRYPT_BIT_BLOB
        {
            public uint cbData;
            public IntPtr pbData;
            public uint cUnusedBits;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CERT_PUBLIC_KEY_INFO
        {
            public CRYPT_ALGORITHM_IDENTIFIER Algorithm;
            public CRYPT_BIT_BLOB PublicKey;
        }

        [DllImport("crypt32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptDecodeObjectEx(
            uint dwCertEncodingType,
            uint lpszStructType,
            IntPtr pbEncoded,
            uint cbEncoded,
            uint dwFlags,
            IntPtr pDecodePara,
            out LocalAllocSafeHandle pvStructInfo,
            out uint pcbStructInfo);

        [DllImport("crypt32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptEncodeObjectEx(
            uint dwCertEncodingType,
            uint lpszStructType,
            IntPtr pvStructInfo,
            uint dwFlags,
            IntPtr pDecodePara,
            out LocalAllocSafeHandle pvEncoded,
            out uint pcbEncoded);

        [DllImport("crypt32.dll", SetLastError = true)]
        internal static extern bool CryptImportPublicKeyInfoEx2(
            [In] uint dwCertEncodingType,
            [In] ref CERT_PUBLIC_KEY_INFO pInfo,
            [In] int dwFlags,
            [In] IntPtr pvAuxInfo,
            [Out] out BCryptKeySafeHandle phKey);

        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern bool CryptExportPublicKeyInfoEx(
            [In] SafeNCryptKeyHandle hCryptProvOrNCryptKey,
            [In] uint dwKeySpec,
            [In] uint dwCertEncodingType,
            [In, MarshalAs(UnmanagedType.LPStr)] string pszPublicKeyObjId,
            [In] uint dwFlags,
            [In] IntPtr pvAuxInfo,
            [In] IntPtr pInfo,
            [In, Out] ref uint pcbInfo);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        internal static extern NTSTATUS BCryptGetProperty(
            [In] BCryptKeySafeHandle hKey,
            [In] string pszProperty,
            [MarshalAs(UnmanagedType.LPArray), In, Out] byte[] pbOutput,
            [In] int cbOutput,
            [Out] out int pcbResult,
            [In] int flags);

        [DllImport("bcrypt.dll", SetLastError = true)]
        internal static extern NTSTATUS BCryptExportKey(
            [In] BCryptKeySafeHandle hKey,
            [In] IntPtr hExportKey,
            [In][MarshalAs(UnmanagedType.LPWStr)] string pszBlobType,
            [Out, MarshalAs(UnmanagedType.LPArray)] byte[] pbOutput,
            [In] int cbOutput,
            [Out] out int pcbResult,
            [In] int dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern NTSTATUS BCryptDestroyKey(IntPtr hKey);

        internal sealed class BCryptKeySafeHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            internal BCryptKeySafeHandle() : base(true) { }

            protected override bool ReleaseHandle()
            {
                return BCryptDestroyKey(this.handle) == NTSTATUS.SUCCESS;
            }
        }
    }
#endif
}
