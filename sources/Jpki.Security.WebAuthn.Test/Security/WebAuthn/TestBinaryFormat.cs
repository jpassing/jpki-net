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

            AssertThat.AreEqual(4, bytesRead);
            AssertThat.AreEqual(4, output.Length);
            AssertThat.AreEqual(
                new byte[] { 0xAA, 0xBB, 0xCC, 0xDD },
                output);
        }

        [Test]
        public void ReadUInt32()
        {
            var input = new byte[] { 0, 0, 0, 0, 0xAA, 0xBB, 0xCC, 0xDD };
            var bytesRead = BigEndian.ReadUInt32(input, 4, out var output);

            AssertThat.AreEqual(4, bytesRead);
            AssertThat.AreEqual(
                0xAABBCCDD,
                output);
        }

        [Test]
        public void ReadUInt16()
        {
            var input = new byte[] { 0, 0, 0, 0, 0xAA, 0xBB, 0xCC, 0xDD };
            var bytesRead = BigEndian.ReadUInt16(input, 4, out var output);

            AssertThat.AreEqual(2, bytesRead);
            AssertThat.AreEqual(
                0xAABB,
                output);
        }

        [Test]
        public void ReadGuid()
        {
            var bigEndianGuid = new byte[] {
                0xCC,
                0x95,
                0x44,
                0x2b,
                0x2e,
                0xf1,
                0x5e,
                0x4d,
                0xef,
                0xb2,
                0x70,
                0xef,
                0xb1,
                0x06,
                0xfa,
                0xcb,
                0x4e,
            };

            var bytesRead = BigEndian.ReadGuid(bigEndianGuid, 1, out var output);

            AssertThat.AreEqual(16, bytesRead);
            AssertThat.AreEqual(
                new Guid("95442b2e-f15e-4def-b270-efb106facb4e"),
                output);
        }
    }
}
