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
using Jpki.Security.Cryptography;
using System.Management.Automation;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Jpki.Powershell.Security.Cryptography
{
    [Cmdlet(VerbsData.ConvertFrom, "Pem")]
    public class ConvertCertificateFromPem : AsyncCmdletBase<X509Certificate2>
    {
        [Parameter(Mandatory = true, ValueFromPipeline = true)]
        public string? Pem { get; set; }

        protected override Task<X509Certificate2> ProcessRecordAsync(
            CancellationToken cancellationToken)
        {
            var certificate = X509Certificate2Extensions
                .CreateFromPem(this.Pem.ExpectNotNull(nameof(this.Pem)));

            return Task.FromResult(certificate);
        }
    }
}
