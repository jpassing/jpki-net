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

using Jpki.Powershell.Runtime.Text;
using NUnit.Framework;
using System.IO;

#if NETFRAMEWORK
using JsonPropertyName = Newtonsoft.Json.JsonPropertyAttribute;
#else
using JsonPropertyName = System.Text.Json.Serialization.JsonPropertyNameAttribute;
#endif

namespace Jpki.Powershell.Test.Runtime.Text
{
    [TestFixture]
    public class TestJson
    {
        public class SomeClass
        {
            [JsonPropertyName("a")]
            public string? A { get; set; }

            [JsonPropertyName("b")]
            public string? B { get; set; }
        }

        //---------------------------------------------------------------------
        // Deserialize.
        //---------------------------------------------------------------------

        [Test]
        public void DeserializeStream()
        {
            using (var stream = new MemoryStream())
            using (var writer = new StreamWriter(stream))
            {
                var json = "{\"a\": \"aa\",\"b\": \"bb\"}";
                writer.Write(json);
                writer.Flush();
                stream.Position = 0;

                var c = Json.Deserialize<SomeClass>(stream);

                AssertThat.NotNull(c);
                AssertThat.AreEqual("aa", c!.A);
                AssertThat.AreEqual("bb", c!.B);
            }
        }

        [Test]
        public void DeserializeString()
        {
            var json = "{\"a\": \"aa\",\"b\": \"bb\"}";
            
            var c = Json.Deserialize<SomeClass>(json);
            
            AssertThat.NotNull(c);
            AssertThat.AreEqual("aa", c!.A);
            AssertThat.AreEqual("bb", c!.B);
        }

        [Test]
        public void WhenStringEmpty_ThenDeserializeStringThrowsException(
            [Values("", " ")] string json)
        {
#if NETFRAMEWORK
            AssertThat.Throws<Newtonsoft.Json.JsonReaderException>(
#else
            AssertThat.Throws<System.Text.Json.JsonException>(
#endif
                () => Json.Deserialize<SomeClass>(json));
        }

        [Test]
        public void WhenSyntaxInvalid_ThenDeserializeStringThrowsException()
        {
#if NETFRAMEWORK
            AssertThat.Throws<Newtonsoft.Json.JsonReaderException>(
#else
            AssertThat.Throws<System.Text.Json.JsonException>(
#endif
                () => Json.Deserialize<SomeClass>("{{"));
        }
    }
}
