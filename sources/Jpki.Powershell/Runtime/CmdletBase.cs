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
using System.Collections.Generic;
using System.Management.Automation;
using System.Threading;

namespace Jpki.Powershell.Runtime
{
    /// <summary>
    /// Base class for Cmdlets.
    /// </summary>
    public abstract class CmdletBase : Cmdlet
    {
        private CancellationTokenSource? cancellationTokenSource;

        private CancellationTokenSource GetCancellationTokenSource()
        {
            this.cancellationTokenSource ??= new CancellationTokenSource();

            return this.cancellationTokenSource;
        }

        /// <summary>
        /// <inheritdoc/>
        /// </summary>
        protected override void StopProcessing()
        {
            this.cancellationTokenSource?.Cancel();

            base.StopProcessing();
        }

        //---------------------------------------------------------------------
        // Begin processing.
        //---------------------------------------------------------------------

        /// <summary>
        /// Overrides the default BeginProcessing method and calls an
        /// async counterpart.
        /// </summary>
        protected override sealed void BeginProcessing()
        {
            try
            {
                BeginProcessing(GetCancellationTokenSource().Token);
            }
            catch (AggregateException e)
            {
                throw e.Unwrap();
            }
        }

        /// <summary>
        /// Overridable in subclasses. When the user cancels a command,
        /// the cancellation token is set.
        /// </summary>
        protected virtual void BeginProcessing(CancellationToken cancellationToken)
        {
        }

        //---------------------------------------------------------------------
        // Process.
        //---------------------------------------------------------------------

        /// <summary>
        /// Overrides the default ProcessRecord method and calls an
        /// async counterpart.
        /// </summary>
        protected override sealed void ProcessRecord()
        {
            try
            {
                ProcessRecord(GetCancellationTokenSource().Token);
            }
            catch (AggregateException e)
            {
                throw e.Unwrap();
            }
        }

        /// <summary>
        /// Overridable in subclasses. When the user cancels a command,
        /// the cancellation token is set.
        /// </summary>
        protected virtual void ProcessRecord(CancellationToken cancellationToken)
        {
        }

        //---------------------------------------------------------------------
        // End processing.
        //---------------------------------------------------------------------

        /// <summary>
        /// Overrides the default EndProcessing method and calls an
        /// async counterpart.
        /// </summary>
        protected override sealed void EndProcessing()
        {
            try
            {
                EndProcessing(GetCancellationTokenSource().Token);
            }
            catch (AggregateException e)
            {
                throw e.Unwrap();
            }

            this.cancellationTokenSource?.Dispose();
            this.cancellationTokenSource = null;
        }

        /// <summary>
        /// Overridable in subclasses. When the user cancels a command,
        /// the cancellation token is set.
        /// </summary>
        protected virtual void EndProcessing(CancellationToken cancellationToken)
        {
        }

        //---------------------------------------------------------------------
        // Unit testing.
        //---------------------------------------------------------------------

        /// <summary>
        /// Execute cmdlet overrides directly. Intended for testing only.
        /// </summary>
        public void Execute()
        {
            BeginProcessing();
            ProcessRecord();
            EndProcessing();
        }
    }
}
