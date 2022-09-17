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

using Jpki.Security.Cryptography;
using NUnit.Framework;
using System;
using System.Security.Cryptography;

namespace Jpki.Test.Security.Cryptography
{
    [TestFixture]
    public class TestEcdsaSignatureFormat
    {
        //---------------------------------------------------------------------
        // Convert.
        //---------------------------------------------------------------------

        [Test]
        public void WhenTargetFormatSameAsSourceFormat_ThenConvertReturnsSignature()
        {
            var signature = new byte[] { 0xAA, 0xBB };

            Assert.AreSame(
                signature,
                EcdsaSignatureFormat.Convert(
                    signature,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation,
                    8));
            Assert.AreSame(
                signature,
                EcdsaSignatureFormat.Convert(
                    signature,
                    DSASignatureFormat.Rfc3279DerSequence,
                    DSASignatureFormat.Rfc3279DerSequence,
                    8));
        }

        [Test]
        public void WhenTargetIsDer_ThenConvertReturnsSignature()
        {
            var ieeeSignature = Convert.FromBase64String(
                "AL2OwNljIvXLnsGVJKhE4V26/KxxfXk29bWbeYAkcWOZI7P28cck9ZuAgDY" +
                "tvgavTcJWKcrVnwvj9QX6iGXYUiz/AWhowTOzKKlqRtLzhtn2AhtXMj6Dj6" +
                "MXsT/KgRCgIbbS/BylStW23UNgGRP83sB4YIx3VKJLG6cAOjU3XHuhn1rz");

            var derSignature = EcdsaSignatureFormat.Convert(
                ieeeSignature,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation,
                DSASignatureFormat.Rfc3279DerSequence,
                521);

            Assert.IsNotNull(derSignature);
            Assert.AreEqual(0x30, derSignature[0]);
            Assert.AreNotEqual(derSignature, ieeeSignature);

            Assert.AreEqual(
                ieeeSignature,
                EcdsaSignatureFormat.Convert(
                    derSignature,
                    DSASignatureFormat.Rfc3279DerSequence,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation,
                    521));
        }

    }
}
