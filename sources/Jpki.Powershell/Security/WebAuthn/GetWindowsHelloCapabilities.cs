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

using Jpki.Powershell.Runtime;
using Jpki.Security.WebAuthn;
using Jpki.Security.WebAuthn.Windows;
using System.Management.Automation;
using System.Threading;
using System.Threading.Tasks;

namespace Jpki.Powershell.Security.WebAuthn
{
    [Cmdlet(VerbsCommon.Get, "WindowsHelloCapabilities")]
    public class GetWindowsHelloCapabilities 
        : AsyncCmdletBase<GetWindowsHelloCapabilities.Capabilities>
    {
        protected override Task<Capabilities> ProcessRecordAsync(
            CancellationToken cancellationToken)
        {
            return Task.FromResult(new Capabilities()
            {
                IsPlatformAuthenticatorAvailable = Authenticators.IsPlatformAuthenticatorAvailable,
#if WINDOWS
                ApiVersionNumber = WindowsHello.ApiVersion,
#endif
            });
        }

        public class Capabilities
        {
            public bool IsPlatformAuthenticatorAvailable { get; internal set; }
            public uint ApiVersionNumber { get; internal set; }
        }
    }
}
