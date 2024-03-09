//
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
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using Jpki;

namespace Jpki
{
    internal static class ParameterExtensions
    {
        public static T AssumeNotNull<T>(this T? obj) where T : class
        {
            Debug.Assert(obj != null);
            return obj!;
        }

        public static T ExpectNotNull<T>(this T? obj, string paramName) where T : class
        {
            if (obj == null)
            {
                throw new ArgumentNullException(paramName);
            }

            return obj;
        }

        public static string ExpectNotNullOrEmpty(this string? str, string paramName)
        {
            if (string.IsNullOrEmpty(str))
            {
                throw new ArgumentException("The parameter is  empty", paramName);
            }

            return str!;
        }

        public static T[] ExpectNotNullOrZeroSized<T>(this T[]? array, string paramName)
        {
            if (array == null || array.Length == 0)
            {
                throw new ArgumentException("The parameter is empty", paramName);
            }

            return array!;
        }

        public static T ExpectDefined<T>(this T enumValue, string paramName)
            where T : struct
        {
            if (!Enum.IsDefined(typeof(T), enumValue))
            {
                throw new ArgumentException("The parameter is invalid", paramName);
            }

            return enumValue;
        }

        public static IEnumerable<T> EnsureNotNull<T>(this IEnumerable<T>? e)
        {
            return e ?? Enumerable.Empty<T>();
        }
    }
}
