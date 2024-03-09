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

using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Host;

namespace Jpki.Powershell.Test.Runtime
{
    /// <summary>
    /// Base class for cmdlet test fixtures.
    /// </summary>
    public abstract class CmdletFixtureBase<TResult>
    {
        private CommandRuntime<TResult>? runtime;

        /// <summary>
        /// Get mock runtime to run Cmdlet with.
        /// </summary>
        protected CommandRuntime<TResult> Runtime
        {
            get
            {
                this.runtime ??= new CommandRuntime<TResult>();

                return this.runtime;
            }
        }

        [TearDown] 
        public void TearDown() 
        {
            this.runtime = null;
        }

        //---------------------------------------------------------------------
        // Inner classes.
        //---------------------------------------------------------------------

        /// <summary>
        /// Mock runtime, inspired by
        /// https://github.com/atheken/nuget/blob/master/test/PowerShellCmdlets.Test/MockCommandRuntime.cs
        /// </summary>
        /// <typeparam name="T">Cmdlet output type</typeparam>
        public class CommandRuntime<T> : ICommandRuntime2
        {
            private readonly List<object> output = new List<object>();

            public List<T> Output
            {
                get => this.output.Cast<T>().ToList();
            }

            public List<ErrorRecord> Errors { get; } = new List<ErrorRecord>();

            public List<string> Warnings { get; } = new List<string>();

            //-----------------------------------------------------------------
            // ICommandRuntime2.
            //-----------------------------------------------------------------

            public PSHost Host => throw new NotImplementedException();

            public PSTransactionContext CurrentPSTransaction => throw new NotImplementedException();

            public bool ShouldContinue(string query, string caption, bool hasSecurityImpact, ref bool yesToAll, ref bool noToAll)
            {
                return true;
            }

            public bool ShouldContinue(string query, string caption, ref bool yesToAll, ref bool noToAll)
            {
                return true;
            }

            public bool ShouldContinue(string query, string caption)
            {
                return true;
            }

            public bool ShouldProcess(string verboseDescription, string verboseWarning, string caption, out ShouldProcessReason shouldProcessReason)
            {
                shouldProcessReason = ShouldProcessReason.None;
                return true;
            }

            public bool ShouldProcess(string verboseDescription, string verboseWarning, string caption)
            {
                return true;
            }

            public bool ShouldProcess(string target, string action)
            {
                return true;
            }

            public bool ShouldProcess(string target)
            {
                return true;
            }

            public void ThrowTerminatingError(ErrorRecord errorRecord)
            {
                if (errorRecord.Exception != null)
                {
                    throw errorRecord.Exception;
                }

                throw new InvalidOperationException(errorRecord.ToString());
            }

            public bool TransactionAvailable()
            {
                return false;
            }

            public void WriteCommandDetail(string text)
            {
            }

            public void WriteDebug(string text)
            {
            }

            public void WriteError(ErrorRecord errorRecord)
            {
                this.Errors.Add(errorRecord);
            }

            public void WriteInformation(InformationRecord informationRecord)
            {
            }

            public void WriteObject(object sendToPipeline, bool enumerateCollection)
            {
                if (!enumerateCollection)
                {
                    WriteObject(sendToPipeline);
                }
                else
                {
                    var enumerator = LanguagePrimitives.GetEnumerator(sendToPipeline);
                    if (enumerator != null)
                    {
                        while (enumerator.MoveNext())
                        {
                            WriteObject(enumerator.Current);
                        }
                    }
                    else
                    {
                        WriteObject(sendToPipeline);
                    }
                }
            }

            public void WriteObject(object sendToPipeline)
            {
                this.output.Add(sendToPipeline);
            }

            public void WriteProgress(long sourceId, ProgressRecord progressRecord)
            {
            }

            public void WriteProgress(ProgressRecord progressRecord)
            {
            }

            public void WriteVerbose(string text)
            {
            }

            public void WriteWarning(string text)
            {
                this.Warnings.Add(text);
            }
        }
    }
}
