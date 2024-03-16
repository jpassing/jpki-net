﻿//
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

using Jpki.Powershell.Runtime.Http;
using NUnit.Framework;
using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;


#if NETFRAMEWORK
using JsonPropertyName = Newtonsoft.Json.JsonPropertyAttribute;
#else
using JsonPropertyName = System.Text.Json.Serialization.JsonPropertyNameAttribute;
#endif

namespace Jpki.Powershell.Test.Runtime.Http
{
    [TestFixture]
    public class TestRestClient
    {
        private static readonly Uri SampleRestUrl = 
            new Uri("https://accounts.google.com/.well-known/openid-configuration");
        
        private static readonly Uri NotFoundUrl =
            new Uri("https://gstatic.com/generate_404");

        private static readonly Uri NoContentUrl =
            new Uri("https://gstatic.com/generate_204");

        private static readonly UserAgent userAgent = new UserAgent(
            "test",
            new Version(1, 0),
            Environment.OSVersion.VersionString);

        public class SampleResource
        {
            [JsonPropertyName("issuer")]
            public string? Issuer { get; set; }
        }

        //---------------------------------------------------------------------
        // GetString.
        //---------------------------------------------------------------------

        [Test]
        public async Task WhenUrlPointsToNoContent_ThenGetStringReturnsEmptyString()
        {
            var client = new RestClient();
            var result = await client
                .GetStringAsync(
                    NoContentUrl,
                    CancellationToken.None)
                .ConfigureAwait(false);

            AssertThat.AreEqual(string.Empty, result);
        }

        [Test]
        public void WhenUrlNotFound_ThenGetStringThrowsException()
        {
            var client = new RestClient();
            AssertThrows.AggregateException<HttpRequestException>(
                () => client.GetStringAsync(
                    NotFoundUrl,
                    CancellationToken.None).Wait());
        }

        //---------------------------------------------------------------------
        // GetJson.
        //---------------------------------------------------------------------

        [Test]
        public async Task WhenUrlPointsToJson_ThenGetJsonReturnsObject()
        {
            var client = new RestClient();
            var result = await client
                .GetJsonAsync<SampleResource>(
                    SampleRestUrl,
                    CancellationToken.None)
                .ConfigureAwait(false);

            AssertThat.IsNotNull(result?.Issuer);
        }

        [Test]
        public async Task WhenUrlPointsToNoContent_ThenGetJsonReturnsNull()
        {
            var client = new RestClient();
            var result = await client
                .GetJsonAsync<SampleResource>(
                    NoContentUrl,
                    CancellationToken.None)
                .ConfigureAwait(false);

            AssertThat.IsNull(result);
        }

        [Test]
        public void WhenUrlNotFound_ThenGetJsonThrowsException()
        {
            var client = new RestClient();
            AssertThrows.AggregateException<HttpRequestException>(
                () => client.GetJsonAsync<SampleResource>(
                    NotFoundUrl,
                    CancellationToken.None).Wait());
        }
    }
}
