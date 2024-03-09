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

using Jpki.Security.WebAuthn;

namespace Jpki.Test.Security.WebAuthn
{
    internal static class Data
    {
        internal static readonly RelyingParty NonResidentRelyingParty = new RelyingParty(
            "https://github.com/jpassing/nwebauthn/",
            "NWebAuthn Test",
            null);
        internal static readonly RelyingParty ResidentRelyingParty = new RelyingParty(
            "https://github.com/jpassing/nwebauthn/#resident",
            "NWebAuthn Test",
            null);

        internal static readonly User User = new User(
            "user@example.com",
            "NWebAuthn Example User",
            "NWebAuthn Example User (Display)",
            null);
    }
}
