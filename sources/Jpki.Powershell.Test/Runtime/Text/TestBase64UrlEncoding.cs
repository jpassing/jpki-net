﻿//
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
using System.Text;

namespace Jpki.Powershell.Test.Runtime.Text
{
    [TestFixture]
    public class TestBase64UrlEncoding
    {
        [Test]
        public void Encode()
        {
            AssertThat.AreEqual(
                "",
                Base64UrlEncoding.Encode(Encoding.ASCII.GetBytes("")));
            AssertThat.AreEqual(
                "MQ",
                Base64UrlEncoding.Encode(Encoding.ASCII.GetBytes("1")));
            AssertThat.AreEqual(
                "MTI",
                Base64UrlEncoding.Encode(Encoding.ASCII.GetBytes("12")));
            AssertThat.AreEqual(
                "MTIz",
                Base64UrlEncoding.Encode(Encoding.ASCII.GetBytes("123")));
            AssertThat.AreEqual(
                "MTIzNA",
                Base64UrlEncoding.Encode(Encoding.ASCII.GetBytes("1234")));
        }

        [Test]
        public void Decode()
        {
            AssertThat.AreEqual(
                "",
                Encoding.ASCII.GetString(Base64UrlEncoding.Decode("")));
            AssertThat.AreEqual(
                "1",
                Encoding.ASCII.GetString(Base64UrlEncoding.Decode("MQ")));
            AssertThat.AreEqual(
                "12",
                Encoding.ASCII.GetString(Base64UrlEncoding.Decode("MTI")));
            AssertThat.AreEqual(
                "123",
                Encoding.ASCII.GetString(Base64UrlEncoding.Decode("MTIz")));
            AssertThat.AreEqual(
                "1234",
                Encoding.ASCII.GetString(Base64UrlEncoding.Decode("MTIzNA")));
        }
    }
}
