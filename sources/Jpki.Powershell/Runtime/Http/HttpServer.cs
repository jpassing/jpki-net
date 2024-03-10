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
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Jpki.Powershell.Runtime.Http
{
    /// <summary>
    /// Base class for a simple HTTP server.
    /// </summary>
    internal class HttpServer : IDisposable
    {
        private readonly CancellationTokenSource cancelByDisposal = new CancellationTokenSource();

        /// <summary>
        /// A random, unused port. Evaluated once to ensure that the random
        /// port stays the same for this instance.
        /// </summary>
        private readonly Lazy<int> randomUnusedPort = new Lazy<int>(
            () => {
                var listener = new TcpListener(IPAddress.Loopback, 0);
                try
                {
                    listener.Start();
                    return ((IPEndPoint)listener.LocalEndpoint).Port;
                }
                finally
                {
                    listener.Stop();
                }
            });

        /// <summary>
        /// Port to listen on.
        /// </summary>
        public ushort? Port { get; set; }

        /// <summary>
        /// Path to listen on.
        /// </summary>
        public string Path { get; set; } = "/";

        /// <summary>
        /// Prefix to listen on.
        /// </summary>
        public string Prefix
        {
            get
            {
                return new UriBuilder()
                {
                    Scheme = "http",
                    Port = this.Port ?? this.randomUnusedPort.Value,
                    Path = this.Path
                }.Uri.ToString();
            }
        }

        /// <summary>
        /// Handle HTTP request, to be overriden.
        /// </summary>
        protected virtual void HandleRequest(
            HttpListenerRequest request,
            HttpListenerResponse response)
        {
            response.StatusCode = (int)HttpStatusCode.NoContent;
        }

        public async Task RunAsync(CancellationToken userCancellationToken)
        {
            var listener = new HttpListener();
            listener.Prefixes.Add(this.Prefix);
            listener.Start();

            //
            // Cancel on user request or when disposed.
            //
            var combinedCancellationToken = CancellationTokenSource
                .CreateLinkedTokenSource(this.cancelByDisposal.Token, userCancellationToken)
                .Token;

            using (combinedCancellationToken.Register(listener.Stop))
            {
                while (true)
                {
                    try
                    {
                        var context = await listener
                            .GetContextAsync()
                            .ConfigureAwait(false);

                        HandleRequest(context.Request, context.Response);
                        context.Response.Close();
                    }
                    catch (Exception) when (combinedCancellationToken.IsCancellationRequested)
                    {
                        combinedCancellationToken.ThrowIfCancellationRequested();

                        //
                        // Next line will never be reached because cancellation will
                        // always have been requested in this catch block.
                        // But it's required to satisfy compiler.
                        //
                        throw new InvalidOperationException();
                    }
                    catch (Exception)
                    {
                        throw;
                    }
                }
            }
        }

        //---------------------------------------------------------------------
        // IDisposable.
        //---------------------------------------------------------------------

        protected virtual void Dispose(bool disposing)
        {
            this.cancelByDisposal.Cancel();
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
