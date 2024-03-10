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
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;

namespace Jpki.Powershell.Test.Runtime
{
    /// <summary>
    /// Assertions for cmdlets.
    /// </summary>
    public static class CmdletAssert
    {
        public static TResult WritesSingleObject<TResult>(CmdletBase cmdlet)
        {
            var runtime = new Runtime();
            cmdlet.Execute(runtime);
            if (runtime.Errors.Any())
            {
                throw new AssertionException(
                    $"Cmdlet wrote one or more non-terminating errors");
            }
            else if (!runtime.Output.Any())
            {
                throw new AssertionException("Cmdlet did write any object");
            }
            else if (runtime.Output.Count > 1)
            {
                throw new AssertionException("Cmdlet wrote more than one object");
            }

            var result = runtime.Output.First();

            if (result == null)
            {
                throw new AssertionException("Cmdlet wrote null");
            }
            else if (result is TResult)
            {
                return (TResult)result;
            }
            else
            {
                throw new AssertionException(
                    $"Expected cmdlet to wrute object of type {typeof(TResult).Name}, " +
                    $"but received object of type {result.GetType().Name}");
            }
        }

        public static TException? ThrowsException<TException>(CmdletBase cmdlet)
            where TException : Exception
        {
            try
            {
                var runtime = new Runtime();
                cmdlet.Execute(runtime);

                throw new AssertionException(
                    $"Excpected exception {typeof(TException).Name}, " +
                    $"but Cmdlet succeeded");
            }
            catch (Exception e) when (e.Unwrap() is TException)
            {
                return (TException)e.Unwrap();
            }
            catch (Exception e)
            {
                throw new AssertionException(
                    $"Excpected exception {typeof(TException).Name}, " +
                    $"but caught {e.GetType().Name}: {e.Message}", e);
            }
        }

        public static ErrorRecord WritesError(CmdletBase cmdlet)
        {
            var runtime = new Runtime();
            cmdlet.Execute(runtime);

            if (!runtime.Errors.Any())
            {
                throw new AssertionException(
                    "Expected cmdlet to write error, but no errors were written");
            }
            else
            {
                return runtime.Errors.First();
            }
        }

        //---------------------------------------------------------------------
        // Inner classes.
        //---------------------------------------------------------------------

        public class Runtime : CmdletBase.ISurrogateRuntime
        {
            public List<object> Output { get; } = new List<object>();

            public List<ErrorRecord> Errors { get; } = new List<ErrorRecord>();

            public List<string> Warnings { get; } = new List<string>();

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
                this.Output.Add(sendToPipeline);
            }

            public void WriteError(ErrorRecord errorRecord)
            {
                this.Errors.Add(errorRecord);
            }

            public void WriteWarning(string text)
            {
                this.Warnings.Add(text);
            }
        }
    }
}
