﻿//
// Copyright 2023 Johannes Passing
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
using System.Reflection;

namespace NUnit.Framework
{
    public static class AssertThrows
    {
        private static Exception Unwrap(this Exception e)
        {
            if (e is AggregateException aggregate &&
                aggregate.InnerException != null)
            {
                return aggregate.InnerException.Unwrap();
            }
            else if (e is TargetInvocationException target &&
                target.InnerException != null)
            {
                return target.InnerException.Unwrap();
            }
            else
            {
                return e;
            }
        }

        public static TActual? AggregateException<TActual>(AsyncTestDelegate code) where TActual : Exception
        {
            return AssertThat.Throws<TActual>(() =>
            {
                try
                {
                    #pragma warning disable VSTHRD002 // Avoid problematic synchronous waits
                    code().Wait();
                    #pragma warning restore VSTHRD002
                }
                catch (AggregateException e)
                {
                    throw e.Unwrap();
                }
            });
        }
    }
}
