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
using System.Net.Http;

namespace Jpki.Powershell.Runtime.Http
{
    internal interface IRestClient : IDisposable
    {
        /// <summary>
        /// User agent to add to HTTP requests.
        /// </summary>
        UserAgent UserAgent { get; }

        TResource Resource<TResource>(Uri url)
            where TResource : RestResourceBase, new();
    }

    internal class RestClient : IRestClient
    {
        //
        // Underlying HTTP client. We keep using the same client so
        // that we can benefit from the underlying connection pool.
        //
        private readonly HttpClient client;

        internal RestClient(
            HttpClient client,
            UserAgent userAgent)
        {
            this.client = client.ExpectNotNull(nameof(client));
            this.UserAgent = userAgent.ExpectNotNull(nameof(userAgent));

            client.DefaultRequestHeaders.UserAgent.ParseAdd(this.UserAgent.ToHeaderValue());
        }

        public RestClient()
            : this(
                  new HttpClient(),
                  UserAgent.Default)
        {
        }

        //---------------------------------------------------------------------
        // IRestClient.
        //---------------------------------------------------------------------

        public UserAgent UserAgent { get; }

        public TResource Resource<TResource>(Uri url)
            where TResource : RestResourceBase, new()
        {
            var resource = new TResource();
            resource.Initialize(this.client, url);
            return resource;
        }

        //---------------------------------------------------------------------
        // IDisposable.
        //---------------------------------------------------------------------

        public void Dispose()
        {
            this.client.Dispose();
        }
    }
}
