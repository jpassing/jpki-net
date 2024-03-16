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
using System;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Jpki.Powershell.Runtime.Http
{
    internal interface IRestClient : IDisposable
    {
        /// <summary>
        /// User agent to add to HTTP requests.
        /// </summary>
        UserAgent UserAgent { get; }

        /// <summary>
        /// Perform a GET request and response as string.
        /// </summary>
        Task<string?> GetStringAsync(
            Uri url,
            CancellationToken cancellationToken); 

        /// <summary>
        /// Perform a GET request and deserialize the JSON response.
        /// </summary>
        Task<TModel?> GetJsonAsync<TModel>(
            Uri url,
            CancellationToken cancellationToken)
            where TModel : class;
    }

    internal class RestClient : IRestClient
    {
        //
        // Use a custom timeout (default is 100sec).
        //
        private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(10);

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

            this.client.Timeout = DefaultTimeout;
        }

        public RestClient()
            : this(
                  new HttpClient(),
                  UserAgent.Default)
        {
        }

        private async Task<TResponse> SendAsync<TResponse>(
            HttpRequestMessage request,
            Func<HttpResponseMessage, Stream, TResponse> unmarshalFunc,
            CancellationToken cancellationToken)
        {
            using (var client = new HttpClient())
            {
                if (this.UserAgent != null)
                {
                    request.Headers.UserAgent.ParseAdd(this.UserAgent.ToHeaderValue());
                }

                using (var response = await client.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken).ConfigureAwait(false))
                {
                    response.EnsureSuccessStatusCode();

                    var stream = await response.Content
                        .ReadAsStreamAsync()
                        .ConfigureAwait(false);

                    return unmarshalFunc(response, stream);
                }
            }
        }

        private async Task<TResponse> GetAsync<TResponse>(
            Uri url,
            Func<HttpResponseMessage, Stream, TResponse> unmarshalFunc,
            CancellationToken cancellationToken)
        {
            using (var request = new HttpRequestMessage(HttpMethod.Get, url))
            {
                return await SendAsync(request, unmarshalFunc, cancellationToken);
            }
        }

        //---------------------------------------------------------------------
        // IRestClient.
        //---------------------------------------------------------------------

        public UserAgent UserAgent { get; }

        public async Task<TModel?> GetJsonAsync<TModel>(
            Uri url,
            CancellationToken cancellationToken)
            where TModel : class
        {
            return await GetAsync(
                url,
                (response, stream) =>
                {
                    if (response.Content.Headers.ContentLength == 0)
                    {
                        return null;
                    }

                    return Json.Deserialize<TModel>(stream);
                },
                cancellationToken);
        }


        public async Task<string?> GetStringAsync(
            Uri url,
            CancellationToken cancellationToken)
        {
            return await GetAsync(
                url,
                (_, stream) =>
                {
                    using (var reader = new StreamReader(stream))
                    {
                        return reader.ReadToEnd();
                    }
                },
                cancellationToken);
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
