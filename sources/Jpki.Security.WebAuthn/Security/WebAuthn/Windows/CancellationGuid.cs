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
using System.Runtime.InteropServices;
using System.Threading;

namespace Jpki.Security.WebAuthn.Windows
{
    internal sealed class CancellationGuid : IDisposable
    {
        private readonly LocalAllocSafeHandle guidHandle;

        internal IntPtr Handle => this.guidHandle.DangerousGetHandle();

        internal CancellationGuid()
        {
            this.guidHandle = LocalAllocSafeHandle.LocalAlloc((uint)Marshal.SizeOf<Guid>());
            var hresult = NativeMethods.WebAuthNGetCancellationId(
                this.guidHandle.DangerousGetHandle());
            if (hresult != HRESULT.S_OK)
            {
                throw WebAuthnException.FromHresult(
                    (HRESULT)hresult,
                    "WebAuthNAuthenticatorMakeCredential",
                    "Creating a cancellation GUID failed");
            }
        }

        public void Bind(CancellationToken token)
        {
            token.Register(() =>
            {
                var hresult = NativeMethods.WebAuthNCancelCurrentOperation(this.Handle);
                if (hresult != HRESULT.S_OK)
                {
                    throw WebAuthnException.FromHresult(
                        (HRESULT)hresult,
                        "WebAuthNAuthenticatorMakeCredential",
                        "Cancelling the WebAuthN operation failed: " + hresult);
                }
            });
        }

        public override string ToString()
        {
            return Marshal
                .PtrToStructure<Guid>(this.Handle)
                .ToString();
        }

        //---------------------------------------------------------------------
        // IDisposable.
        //---------------------------------------------------------------------

        public void Dispose()
        {
            this.guidHandle.Dispose();
        }
    }
}
