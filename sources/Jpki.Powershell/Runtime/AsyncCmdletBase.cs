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

using System.Threading;
using System.Threading.Tasks;

#pragma warning disable VSTHRD002 // Avoid problematic synchronous waits

namespace Jpki.Powershell.Runtime
{
    public abstract class AsyncCmdletBase<TResult> : CmdletBase
    {
        //---------------------------------------------------------------------
        // Begin processing.
        //---------------------------------------------------------------------

        protected override sealed void BeginProcessing(CancellationToken cancellationToken)
        {
            BeginProcessingAsync(cancellationToken).Wait(cancellationToken);
        }

        protected virtual Task BeginProcessingAsync(CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        //---------------------------------------------------------------------
        // Process.
        //---------------------------------------------------------------------

        protected override sealed void ProcessRecord(CancellationToken cancellationToken)
        {
            var result = ProcessRecordAsync(cancellationToken)
                .GetResult<TResult>(cancellationToken);
            if (result != null)
            {
                WriteObject(result, true);
            }
        }

        protected abstract Task<TResult> ProcessRecordAsync(CancellationToken cancellationToken);


        //---------------------------------------------------------------------
        // End processing.
        //---------------------------------------------------------------------

        protected override sealed void EndProcessing(CancellationToken cancellationToken)
        {
            EndProcessingAsync(cancellationToken).Wait(cancellationToken);
        }

        protected virtual Task EndProcessingAsync(CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }
    }
}
