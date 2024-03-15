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


namespace Jpki.Security.WebAuthn.Windows
{

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

    internal enum WEBAUTHN_CTAP_TRANSPORT : uint
    {
        USB = 0x00000001,
        NFC = 0x00000002,
        BLE = 0x00000004,
        TEST = 0x00000008,
        INTERNAL = 0x00000010,
        FLAGS_MASK = 0x0000001F,
    }
}
