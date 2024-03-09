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
using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Threading;

namespace Jpki.Powershell
{
    /// <summary>
    /// Base class for all Cmdlets.
    /// </summary>
    public abstract class CmdletBase : Cmdlet
    {
        private CancellationTokenSource? cancellationTokenSource;

        private CancellationTokenSource GetCancellationTokenSource()
        {
            if (this.cancellationTokenSource == null)
            {
                this.cancellationTokenSource = new CancellationTokenSource();
            }

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

        /// <summary>
        /// Write a collection of objects, one at a time.
        /// </summary>
        protected void WriteCollection<T>(IEnumerable<T> objects)
        {
            foreach (var o in objects)
            {
                WriteObject(o);
            }
        }

        //---------------------------------------------------------------------
        // Begin processing.
        //---------------------------------------------------------------------

        /// <summary>
        /// <inheritdoc/>
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
        /// Overridable in subclasses.
        /// </summary>
        protected virtual void BeginProcessing(CancellationToken cancellationToken)
        {
        }

        //---------------------------------------------------------------------
        // Process.
        //---------------------------------------------------------------------

        /// <summary>
        /// <inheritdoc/>
        /// </summary>
        protected override sealed void ProcessRecord()
        {
            try
            {
                ProcessRecord(GetCancellationTokenSource().Token);
            }
            catch (AggregateException e)
            {
                // TODO: Write error?
                throw e.Unwrap();
            }
        }

        /// <summary>
        /// Overridable in subclasses.
        /// </summary>
        protected virtual void ProcessRecord(CancellationToken cancellationToken)
        {
        }

        //---------------------------------------------------------------------
        // End processing.
        //---------------------------------------------------------------------

        /// <summary>
        /// <inheritdoc/>
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
        /// Overridable in subclasses.
        /// </summary>
        protected virtual void EndProcessing(CancellationToken cancellationToken)
        {
        }
    }
}
