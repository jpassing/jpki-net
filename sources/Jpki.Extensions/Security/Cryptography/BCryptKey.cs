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
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Jpki.Security.Cryptography
{
    internal class BCryptKey
    {
        public NativeMethods.BCryptKeySafeHandle Handle { get; }

        public BCryptKey(NativeMethods.BCryptKeySafeHandle handle)
        {
            this.Handle = handle;
        }

        public bool TryGetProperty(
            string property,
            [NotNullWhen(true)] out string? value)
        {
            var status = NativeMethods.BCryptGetProperty(
                this.Handle,
                property,
                null!,
                0,
                out var bufferSize,
                0);
            if (status != NTSTATUS.SUCCESS || bufferSize == 0)
            {
                value = null;
                return false;
            }

            var buffer = new byte[bufferSize];
            status = NativeMethods.BCryptGetProperty(
                this.Handle,
                property,
                buffer,
                ((byte)bufferSize),
                out bufferSize,
                0);

            if (status != NTSTATUS.SUCCESS || bufferSize == 0)
            {
                value = null;
                return false;
            }

            //
            // The property is a zero-terminated Unicode string.
            //
            Debug.Assert(bufferSize == buffer.Length);
            Debug.Assert((buffer.Length % 2) == 0);
            Debug.Assert(buffer[buffer.Length - 1] == '\0');
            Debug.Assert(buffer[buffer.Length - 2] == '\0');

            value = Encoding.Unicode.GetString(buffer, 0, buffer.Length - 2);
            return true;
        }

        public byte[] ExportKeyBlob(string blobType)
        {
            var status = NativeMethods.BCryptExportKey(
                this.Handle,
                IntPtr.Zero,
                blobType,
                null!,
                0,
                out var blobSize,
                0);
            if (status != NTSTATUS.BUFFER_TOO_SMALL && status != NTSTATUS.SUCCESS)
            {
                throw new CryptographicException(Marshal.GetLastWin32Error());
            }

            var blob = new byte[blobSize];
            status = NativeMethods.BCryptExportKey(
                this.Handle,
                IntPtr.Zero,
                blobType,
                blob,
                blobSize,
                out blobSize,
                0);
            if (status != NTSTATUS.SUCCESS)
            {
                throw new CryptographicException(Marshal.GetLastWin32Error());
            }

            Debug.Assert(blobSize == blob.Length);

            return blob;
        }
    }
}
#endif