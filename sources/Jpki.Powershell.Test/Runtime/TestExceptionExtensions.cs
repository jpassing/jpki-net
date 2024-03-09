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
using System.Reflection;
using System;

namespace Jpki.Powershell.Test.Runtime
{
    [TestFixture]
    public class TestExceptionExtensions
    {
        private static Exception CreateException()
        {
            try
            {
                throw new ArgumentException("sample");
            }
            catch (ArgumentException e)
            {
                return e;
            }
        }

        //---------------------------------------------------------------------
        // Unwrap.
        //---------------------------------------------------------------------

        [Test]
        public void WhenRegularException_ThenUnwrapDoesNothing()
        {
            var ex = new ApplicationException();

            var unwrapped = ex.Unwrap();

            AssertThat.AreSame(ex, unwrapped);
        }

        [Test]
        public void WhenAggregateException_ThenUnwrapReturnsFirstInnerException()
        {
            var inner1 = new ApplicationException();
            var inner2 = new ApplicationException();
            var aggregate = new AggregateException(inner1, inner2);

            var unwrapped = aggregate.Unwrap();

            AssertThat.AreSame(inner1, unwrapped);
        }

        [Test]
        public void WhenAggregateExceptionContainsAggregateException_ThenUnwrapReturnsFirstInnerException()
        {
            var inner1 = new ApplicationException();
            var inner2 = new ApplicationException();
            var aggregate = new AggregateException(
                new AggregateException(
                    new TargetInvocationException(inner1)), inner2);

            var unwrapped = aggregate.Unwrap();

            AssertThat.AreSame(inner1, unwrapped);
        }

        [Test]
        public void WhenAggregateExceptionWithoutInnerException_ThenUnwrapDoesNothing()
        {
            var aggregate = new AggregateException();
            var unwrapped = aggregate.Unwrap();

            AssertThat.AreSame(aggregate, unwrapped);
        }

        [Test]
        public void WhenTargetInvocationException_ThenUnwrapReturnsInnerException()
        {
            var inner = new ApplicationException();
            var target = new TargetInvocationException("", inner);

            var unwrapped = target.Unwrap();

            AssertThat.AreSame(inner, unwrapped);
        }
    }
}
