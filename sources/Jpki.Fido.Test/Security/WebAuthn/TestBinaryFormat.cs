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

using Jpki.Format;
using NUnit.Framework;
using System;

namespace Jpki.Test.Security.WebAuthn
{
    [TestFixture]
    public class TestBinaryFormat
    {
        [Test]
        public void ReadByteArray()
        {
            var input = new byte[] { 0, 0, 0, 0, 0xAA, 0xBB, 0xCC, 0xDD };
            var bytesRead = BigEndian.ReadByteArray(input, 4, 4, out var output);

            Assert.AreEqual(4, bytesRead);
            Assert.AreEqual(4, output.Length);
            Assert.AreEqual(
                new byte[] { 0xAA, 0xBB, 0xCC, 0xDD },
                output);
        }

        [Test]
        public void ReadUInt32()
        {
            var input = new byte[] { 0, 0, 0, 0, 0xAA, 0xBB, 0xCC, 0xDD };
            var bytesRead = BigEndian.ReadUInt32(input, 4, out var output);

            Assert.AreEqual(4, bytesRead);
            Assert.AreEqual(
                0xAABBCCDD,
                output);
        }

        [Test]
        public void ReadUInt16()
        {
            var input = new byte[] { 0, 0, 0, 0, 0xAA, 0xBB, 0xCC, 0xDD };
            var bytesRead = BigEndian.ReadUInt16(input, 4, out var output);

            Assert.AreEqual(2, bytesRead);
            Assert.AreEqual(
                0xAABB,
                output);
        }

        [Test]
        public void ReadGuid()
        {
            var guid = Guid.NewGuid().ToByteArray();
            var bytesRead = BigEndian.ReadGuid(guid, 0, out var output);

            Assert.AreEqual(16, bytesRead);
            Assert.AreEqual(
                guid,
                output.ToByteArray());
        }
    }
}
