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

using Jpki.Security.WebAuthn.Windows;

namespace Jpki.Security.WebAuthn
{
    //
    // NB. The WebAuthn specification doesn't define numeric values
    // for these enums, so we're using the Windows Hello values.
    //

    public enum AuthenticatorAttachment : uint
    {
        Any = WEBAUTHN_AUTHENTICATOR_ATTACHMENT.ANY,
        Platform = WEBAUTHN_AUTHENTICATOR_ATTACHMENT.PLATFORM,
        CrossPlatform = WEBAUTHN_AUTHENTICATOR_ATTACHMENT.CROSS_PLATFORM,
        CrossPlatformU2fV2 = WEBAUTHN_AUTHENTICATOR_ATTACHMENT.CROSS_PLATFORM_U2F_V2,
    }

    public enum UserVerificationRequirement : uint
    {
        Any = WEBAUTHN_USER_VERIFICATION_REQUIREMENT.ANY,
        Required = WEBAUTHN_USER_VERIFICATION_REQUIREMENT.REQUIRED,
        Preferred = WEBAUTHN_USER_VERIFICATION_REQUIREMENT.PREFERRED,
        Discouraged = WEBAUTHN_USER_VERIFICATION_REQUIREMENT.DISCOURAGED,
    }

    public enum AttestationConveyance : uint
    {
        Any = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE.ANY,
        None = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE.NONE,
        Indirect = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE.INDIRECT,
        Direct = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE.DIRECT,
    }

    public enum ResidentKeyRequirement
    {
        Any,
        Preferred,
        Required
    }
}
