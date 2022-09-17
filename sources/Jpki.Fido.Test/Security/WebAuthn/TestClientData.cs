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

using Jpki.Security.Cryptography.Cose;
using Jpki.Security.WebAuthn;
using NUnit.Framework;
using System;
using System.Text;

namespace Jpki.Test.Security.WebAuthn
{
    [TestFixture]
    public class TestClientData
    {
        //---------------------------------------------------------------------
        // Ctor.
        //---------------------------------------------------------------------

        [Test]
        public void WhenHashAlgorithmUnknown_ThenConstructorThrowsException()
        {
            Assert.Throws<ArgumentException>(
                () => new ClientData(new byte[] { 1, 2, 3 }, (CoseHashAlgorithm)0));
        }

        //---------------------------------------------------------------------
        // Hash.
        //---------------------------------------------------------------------

        [Test]
        public void WhenUsingDefaulrHashAlgorithm_ThenHashReturnsSha256()
        {
            //
            // Sample data from U2F specification,
            // see https://fidoalliance.org/specs/fido-u2f-v1.1-id-20160915/fido-u2f-raw-message-formats-v1.1-id-20160915.html
            //

            var clientDataBase64 =
                "eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW" +
                "5nZSI6InZxclM2V1hEZTFKVXM1X2MzaTQtTGtLSUhSci0zWFZiM2F6dUE1VGlm" +
                "SG8iLCJjaWRfcHVia2V5Ijp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4Ij" +
                "oiSHpRd2xmWFg3UTRTNU10Q0NuWlVOQnczUk16UE85dE95V2pCcVJsNHRKOCIs" +
                "InkiOiJYVmd1R0ZMSVp4MWZYZzN3TnFmZGJuNzVoaTQtXzctQnhoTWxqdzQySH" +
                "Q0In0sIm9yaWdpbiI6Imh0dHA6Ly9leGFtcGxlLmNvbSJ9";

            var clientDataJson = Encoding.UTF8.GetString(Convert.FromBase64String(clientDataBase64));
            var clientData = ClientData.FromJson(clientDataJson);

            CollectionAssert.AreEqual(
                Convert.FromBase64String("QULSHADZT/udUEraj5m3IfSxka5ON8oBQPaWtpg8+ss="),
                clientData.Hash);
        }
    }
}
