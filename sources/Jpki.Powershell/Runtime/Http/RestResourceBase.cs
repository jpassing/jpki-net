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

using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Jpki.Powershell.Runtime.Http
{
    internal abstract class RestResourceBase
    {
        private Uri? baseUri;
        private HttpClient? client;

        public abstract string ExpectedContentType { get; }

        public Uri BaseUri
        {
            get => this.baseUri ?? throw new InvalidOperationException(
                "Resource has not been initialized");
            private set => this.baseUri = value;
        }

        public HttpClient Client
        {
            get => this.client ?? throw new InvalidOperationException(
                "Resource has not been initialized");
            private set => this.client = value;
        }

        internal void Initialize(HttpClient client, Uri uri)
        {
            this.Client = client;
            this.BaseUri = uri;
        }

        /// <summary>
        /// Base class for REST requests.
        /// </summary>
        public abstract class RequestBase
        {
            private readonly RestResourceBase resource;

            protected RequestBase(RestResourceBase resource)
            {
                this.resource = resource;
                this.Uri = resource.BaseUri;
            }

            //
            // Request timeout.
            //
            public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(10);

            /// <summary>
            /// Request URI.
            /// </summary>
            public Uri Uri { get; set; } 

            /// <summary>
            /// Initialze a HTTP request message.
            /// </summary>
            /// <returns></returns>
            internal abstract HttpRequestMessage CreateRequest();

            /// <summary>
            /// Send the request.
            /// </summary>
            internal async Task<HttpResponseMessage> ExecuteAsync(
                CancellationToken cancellationToken)
            {
                using (var request = CreateRequest())
                {
                    var response = await this.resource
                        .Client
                        .SendAsync(
                            request,
                            HttpCompletionOption.ResponseHeadersRead,
                            cancellationToken)
                        .ConfigureAwait(false);

                    response.EnsureSuccessStatusCode();

                    var contentType = response.Content.Headers.ContentType?.MediaType;
                    if (contentType != null &&
                        contentType != this.resource.ExpectedContentType)
                    {
                        throw new UnexpectedContentTypeException(
                            $"Received unexpected content type '{contentType}' " +
                            $"(expected: '{this.resource.ExpectedContentType}')");
                    }

                    return response;
                }
            }
        }

        /// <summary>
        /// Base class for REST responses.
        /// </summary>
        public abstract class ResponseBase
        {
            /// <summary>
            /// HTTP status code.
            /// </summary>
            public HttpStatusCode StatusCode { get; }

            protected ResponseBase(HttpStatusCode statusCode)
            {
                this.StatusCode = statusCode;
            }
        }
    }

    public class UnexpectedContentTypeException : HttpRequestException
    {
        internal UnexpectedContentTypeException(string message) : base(message)
        {
        }
    }
}
