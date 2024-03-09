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
    public enum Transport : uint
    {
        Usb = NativeMethods.WEBAUTHN_CTAP_TRANSPORT.USB,
        Nfc = NativeMethods.WEBAUTHN_CTAP_TRANSPORT.NFC,
        Ble = NativeMethods.WEBAUTHN_CTAP_TRANSPORT.BLE,
        Test = NativeMethods.WEBAUTHN_CTAP_TRANSPORT.TEST,
        Internal = NativeMethods.WEBAUTHN_CTAP_TRANSPORT.INTERNAL,
        Any = NativeMethods.WEBAUTHN_CTAP_TRANSPORT.FLAGS_MASK
    }
}
