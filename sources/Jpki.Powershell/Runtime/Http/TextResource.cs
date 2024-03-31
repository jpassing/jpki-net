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

using System.Net.Http;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Jpki.Powershell.Runtime.Http
{
    internal class TextResource : RestResourceBase
    {
        public override string ExpectedContentType => "text/plain";

        /// <summary>
        /// Create a new GET request.
        /// </summary>
        public GetRequest Get()
        {
            return new GetRequest(this);
        }

        //---------------------------------------------------------------------
        // Inner classes.
        //---------------------------------------------------------------------

        /// <summary>
        /// GET request for a  payload.
        /// </summary>
        public class GetRequest : RequestBase
        {
            public GetRequest(TextResource resource) : base(resource)
            {
            }

            internal override HttpRequestMessage CreateRequest()
            {
                return new HttpRequestMessage(HttpMethod.Get, this.Uri);
            }

            public async new Task<Response> ExecuteAsync(
                CancellationToken cancellationToken)
            {
                using (var response = await base
                    .ExecuteAsync(cancellationToken)
                    .ConfigureAwait(false))
                {
                    var body = await response.Content
                        .ReadAsStringAsync()
                        .ConfigureAwait(false);

                    return new Response(response.StatusCode, body);
                }
            }
        }

        /// <summary>
        /// Text response
        /// </summary>
        public class Response : ResponseBase
        {
            public Response(
                HttpStatusCode statusCode,
                string? body) : base(statusCode)
            {
                this.Body = body;
            }

            public string? Body { get; }
        }
    }
}
