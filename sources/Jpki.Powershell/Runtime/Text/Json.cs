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


using System.IO;

#if NETFRAMEWORK
using Newtonsoft.Json;
#else
using System.Text.Json;
#endif

namespace Jpki.Powershell.Runtime.Text
{
    /// <summary>
    /// Deserialize JSON using either Newtonsoft.Json (NetFx) or
    /// System.Text.Json (.NET).
    /// </summary>
    internal static class Json 
    {
        public static T? Deserialize<T>(Stream stream) where T : class
        {
#if NETFRAMEWORK
            using (var reader = new StreamReader(stream))
            using (var jsonReader = new JsonTextReader(reader))
            {
                return new JsonSerializer().Deserialize<T>(jsonReader);
            }
#else
            return JsonSerializer.Deserialize<T>(stream);
#endif
        }

        public static T? Deserialize<T>(string json) where T : class
        {
#if NETFRAMEWORK
            if (string.IsNullOrWhiteSpace(json))
            {
                throw new JsonReaderException("The input string does not contain any JSON data");
            }

            using (var reader = new StringReader(json))
            using (var jsonReader = new Newtonsoft.Json.JsonTextReader(reader))
            {
                return new JsonSerializer().Deserialize<T>(jsonReader);
            }
#else
            return JsonSerializer.Deserialize<T>(json);
#endif
        }
    }
}
