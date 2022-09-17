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

using NUnit.Framework;

namespace Jpki.Test.Security.WebAuthn
{
    [TestFixture]
    public class TestAttestationStatement
    {

        //[Test]
        //public void WhenStatementContainsValidSignature_ThenVerifySignatureSucceeds()
        //{
        //    //
        //    // Sample data from U2F specification,
        //    // see https://fidoalliance.org/specs/fido-u2f-v1.1-id-20160915/fido-u2f-raw-message-formats-v1.1-id-20160915.html
        //    //
        //    var certificate = new X509Certificate(Convert.FromBase64String(
        //        "MIIBPDCB5KADAgECAgpHkBKAABFVlXNSMAoGCCqGSM49BAMCMBcxFTATBgNVBA" +
        //        "MTDEdudWJieSBQaWxvdDAeFw0xMjA4MTQxODI5MzJaFw0xMzA4MTQxODI5MzJa" +
        //        "MDExLzAtBgNVBAMTJlBpbG90R251YmJ5LTAuNC4xLTQ3OTAxMjgwMDAxMTU1OT" +
        //        "U3MzUyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjWF+ZclQjmS8xWc6yCpn" +
        //        "mdo8FEZoLCWMRj//31jf0vo+bDeLU9eVxKTf+0GZ7deGLyOrrwIDtLiRG6BWmZ" +
        //        "ThATAKBggqhkjOPQQDAgNHADBEAiBgzbYGHpwiJi0arB2W2McIKbI2ZTHdomiD" +
        //        "LLg2vNMN+gIgYxsUWfCeYzAFVyLI2Jt/SIg7kIm4jWDR2XlZArMEEN8="));
        //    var signature = Convert.FromBase64String(
        //        "APDmpqlwQqTx8ch/X31EMVsthSwt9ceZHMZiQb9wctHEQULSHADZT/udUEraj5" +
        //        "m3IfSxka5ON8oBQPaWtpg8+ssqVS39t0d+1l/YQTP4YZYBCyIVtX2nXTFbe56P" +
        //        "4uOSWmAZVRurYdFlkWWcuvALSVD3q/5mYOLgBvdoaLdy1wwlBLF0vEnHyiVLcN" +
        //        "LlwgfO6c8XSCDr136jxlUIwm2lG2V8HMa5UvhiFpeTZILaCm09OCalkJXa9s18" +
        //        "A+LmA4XS9tk=");
        //    var clientDataJson = Encoding.UTF8.GetString(Convert.FromBase64String(
        //        "eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW" +
        //        "5nZSI6InZxclM2V1hEZTFKVXM1X2MzaTQtTGtLSUhSci0zWFZiM2F6dUE1VGlm" +
        //        "SG8iLCJjaWRfcHVia2V5Ijp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4Ij" +
        //        "oiSHpRd2xmWFg3UTRTNU10Q0NuWlVOQnczUk16UE85dE95V2pCcVJsNHRKOCIs" +
        //        "InkiOiJYVmd1R0ZMSVp4MWZYZzN3TnFmZGJuNzVoaTQtXzctQnhoTWxqdzQySH" +
        //        "Q0In0sIm9yaWdpbiI6Imh0dHA6Ly9leGFtcGxlLmNvbSJ9"));

        //    var clientData = ClientData.FromJson(clientDataJson);

        //    var privateKey = new ECParameters()
        //    {
        //        D = Convert.FromBase64String("8/zMDQDYAxlU+Qhk1Dwkf0v18GZca1DMF3SaJ9HPdmQ="),
        //        Q = new ECPoint()
        //        {
        //            X = Convert.FromBase64String("jWF+ZclQjmS8xWc6yCpnmdo8FEZoLCWMRj//31jf0vo="),
        //            Y = Convert.FromBase64String("Pmw3i1PXlcSk3/tBme3Xhi8jq68CA7S4kRugVpmU4QE=")
        //        },
        //        Curve = ECCurve.NamedCurves.nistP256
        //    };
        //}
    }
}
