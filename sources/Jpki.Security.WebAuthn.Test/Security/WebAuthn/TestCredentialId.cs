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

using Jpki.Security.WebAuthn;
using NUnit.Framework;

namespace Jpki.Test.Security.WebAuthn
{
    [TestFixture]
    public class TestCredentialId
    {
        [Test]
        public void ToStringReturnsBase64()
        {
            var c1 = new CredentialId(new byte[] { 0xAA, 0xBB, 0xCC, 0xDD });
            AssertThat.AreEqual("qrvM3Q==", c1.ToString());
        }

        [Test]
        public void ParseConvertsBase64()
        {
            var c1 = CredentialId.Parse("qrvM3Q==");
            var c2 = new CredentialId(new byte[] { 0xAA, 0xBB, 0xCC, 0xDD });

            AssertThat.AreEqual(c1, c2);
        }

        //---------------------------------------------------------------------
        // Equality.
        //---------------------------------------------------------------------

        [Test]
        public void Equals()
        {
            var c1 = new CredentialId(new byte[] { 0xAA, 0xBB, 0xCC, 0xDD });
            var c2 = new CredentialId(new byte[] { 0xAA, 0xBB, 0xCC, 0xDD });

            AssertThat.IsTrue(c1.Equals(c2));
            AssertThat.IsTrue(c1 == c2);
            AssertThat.IsFalse(c1 != c2);
            AssertThat.AreEqual(c1.GetHashCode(), c2.GetHashCode());
        }

        [Test]
        public void NotEquals()
        {
            var c1 = new CredentialId(new byte[] { 0xAA, 0xBB, 0xCC });
            var c2 = new CredentialId(new byte[] { 0xAA, 0xBB, 0xCC, 0xDD });

            AssertThat.IsFalse(c1.Equals(c2));
            AssertThat.IsTrue(c1 != c2);
            AssertThat.IsFalse(c1 == c2);
            AssertThat.AreNotEqual(c1.GetHashCode(), c2.GetHashCode());
        }
    }
}
