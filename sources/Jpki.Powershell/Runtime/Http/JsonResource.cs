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

using Jpki.Powershell.Runtime.Text;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Jpki.Powershell.Runtime.Http
{
    internal class JsonResource<TBody> : RestResourceBase
        where TBody : class
    {
        public override string ExpectedContentType => "application/json";

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
        /// GET request for a JSON payload.
        /// </summary>
        public class GetRequest : RequestBase
        {
            public GetRequest(JsonResource<TBody> resource) : base(resource)
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
                using (var stream = await response.Content
                    .ReadAsStreamAsync()
                    .ConfigureAwait(false))
                {
                    TBody? body = null;
                    if (response.Content.Headers.ContentLength > 0)
                    {
                        body = Json.Deserialize<TBody>(stream);
                    }

                    return new Response(response.StatusCode, body);
                }
            }
        }

        /// <summary>
        /// JSON response
        /// </summary>
        public class Response : ResponseBase
        {
            public Response(
                HttpStatusCode statusCode,
                TBody? body) : base(statusCode)
            {
                this.Body = body;
            }

            public TBody? Body { get; }
        }
    }
}
