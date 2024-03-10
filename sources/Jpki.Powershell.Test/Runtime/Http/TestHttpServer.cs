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

using Jpki.Powershell.Runtime.Http;
using NUnit.Framework;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Jpki.Powershell.Test.Runtime.Http
{
    [TestFixture]
    public class TestHttpServer
    {
        //---------------------------------------------------------------------
        // Dispose.
        //---------------------------------------------------------------------

        [Test]
        public void DisposeStopsListener()
        {
            Task runTask;
            using (var server = new HttpServer())
            {
                runTask = server.RunAsync(CancellationToken.None);
            }

            AssertThrows.AggregateException<TaskCanceledException>(() => runTask.Wait());
        }

        //---------------------------------------------------------------------
        // Prefix.
        //---------------------------------------------------------------------

        [Test]
        public void WhenCustomPortSet_ThenPrefixUsesPort()
        {
            using (var server = new HttpServer()
            {
                Port = 8080
            })
            {
                AssertThat.AreEqual("http://localhost:8080/", server.Prefix);
            }
        }

        [Test]
        public void WhenCustomPortNotSet_ThenPrefixUsesRandomPort()
        {
            using (var server = new HttpServer())
            {
                //
                // Port must not changed when Prefix is read multiple times.
                //
                AssertThat.AreEqual(server.Prefix, server.Prefix);
            }
        }

        //---------------------------------------------------------------------
        // Request handling.
        //---------------------------------------------------------------------

        [Test]
        public async Task DefaultResponse()
        {
            using (var server = new HttpServer())
            {
                _ = server.RunAsync(CancellationToken.None);

                using (var client = new HttpClient())
                {
                    var response = await client
                        .GetAsync(server.Prefix)
                        .ConfigureAwait(false);

                    AssertThat.AreEqual(HttpStatusCode.NoContent, response.StatusCode);
                }
            }
        }
    }
}
