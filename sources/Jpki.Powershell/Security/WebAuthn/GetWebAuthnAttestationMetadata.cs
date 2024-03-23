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
using Jpki.Powershell.Runtime.Http;
using Jpki.Powershell.Runtime.Text;
using Jpki.Security.WebAuthn.Metadata;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Jpki.Powershell.Security.WebAuthn
{
    [Cmdlet(VerbsCommon.Get, "WebAuthnAttestationMetadata")]
    public class GetWebAuthnAttestationMetadata
        : AsyncCmdletBase<IEnumerable<MetadataBlob.Entry>> // TODO: test
    {
        private const string FidoParameterSet = null;
        private const string U2fParameterSet = null;

        //---------------------------------------------------------------------
        // Fido parameter set.
        //---------------------------------------------------------------------

        [Parameter(Mandatory = false, ParameterSetName = nameof(FidoParameterSet))]
        public string? Aaguid { get; set; }

        //---------------------------------------------------------------------
        // Detailed parameter set.
        //---------------------------------------------------------------------

        [Parameter(Mandatory = false, ParameterSetName = nameof(U2fParameterSet))]
        public string? Aaid { get; set; }

        //---------------------------------------------------------------------
        // Overrides.
        //---------------------------------------------------------------------

        protected override async Task<IEnumerable<MetadataBlob.Entry>> ProcessRecordAsync(
            CancellationToken cancellationToken)
        {
            var payload = await MdsMetadataResource
                .DownloadAsync(cancellationToken)
                .ConfigureAwait(false);

            return payload
                .Entries
                .EnsureNotNull()
                .Where(e => this.Aaguid == null || this.Aaguid == e.AaguidString)
                .Where(e => this.Aaid == null || this.Aaguid == e.Aaid);
        }

        private class MdsMetadataResource : TextResource
        {
            /// <summary>
            /// Metadata URL as published on https://fidoalliance.org/metadata/.
            /// </summary>
            public static readonly Uri Url = new Uri("https://mds3.fidoalliance.org/");

            public override string ExpectedContentType => "application/octet-stream";

            public static async Task<MetadataBlob> DownloadAsync(CancellationToken cancellationToken)
            {
                using (var restClient = new RestClient())
                {
                    var metadataJwt = await restClient
                        .Resource<MdsMetadataResource>(Url)
                        .Get()
                        .ExecuteAsync(cancellationToken)
                        .ConfigureAwait(false);

                    return MetadataBlob.ParseUntrusted(metadataJwt.Body);
                }
            }
        }
    }
}
