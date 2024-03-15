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


using Jpki.Interop;
using Jpki.Security.WebAuthn.Windows;
using System;

namespace Jpki.Security.WebAuthn
{
    public static class Authenticators
    {
        public static IAuthenticator WindowsHello// TODO: test non-windows
        {
#if WINDOWS || NETFRAMEWORK
            get => new WindowsHello();
#else
            get => throw new PlatformNotSupportedException(
            "Windows Hello is not supported on this platform");
#endif
        }

        //---------------------------------------------------------------------
        // Capabilities.
        //---------------------------------------------------------------------

        public static bool IsPlatformAuthenticatorAvailable // TODO: test non-windows
        {
#if WINDOWS || NETFRAMEWORK
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
#else
            get => false;
#endif
        }
    }
}
