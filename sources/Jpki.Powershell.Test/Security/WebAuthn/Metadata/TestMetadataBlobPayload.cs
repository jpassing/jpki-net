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
using Jpki.Security.WebAuthn.Metadata;
using NUnit.Framework;
using System;
using System.Linq;

namespace Jpki.Powershell.Test.Security.WebAuthn.Metadata
{
    [TestFixture]
    public class TestMetadataBlobPayload
    {
        [Test]
        public void GoogleTitanV2()
        {
            var blob = Json.Deserialize<MetadataBlob>(
                MdsSampleData.MetadataBlobs.GoogleTitanV2)!;

            AssertThat.NotNull(blob);
            AssertThat.AreEqual("...", blob.LegalHeader);
            AssertThat.AreEqual(64, blob.No);
            AssertThat.AreEqual(2024, blob.NextUpdate!.Value.Year);
            AssertThat.AreEqual(1, blob.Entries!.Count);

            var entry = blob.Entries!.First();

            AssertThat.AreEqual(
                new Guid("42b4fb4a-2866-43b2-9bf7-6c6669c2e5d3"),
                entry.Aaguid);
            AssertThat.AreEqual(
                new Guid("42b4fb4a-2866-43b2-9bf7-6c6669c2e5d3"),
                entry.MetadataStatement!.Aaguid);

            AssertThat.AreEqual(2, entry.StatusReports!.Count);
            AssertThat.AreEqual(AuthenticatorStatus.FIDO_CERTIFIED_L1, entry.StatusReports[0].Status);
            AssertThat.AreEqual("FIDO20020230612002", entry.StatusReports[0].CertificateNumber);
            AssertThat.AreEqual("1.4.0", entry.StatusReports[0].CertificationPolicyVersion);
            AssertThat.AreEqual("1.5.0", entry.StatusReports[0].CertificationRequirementsVersion);

            AssertThat.AreEqual(AuthenticatorStatus.FIDO_CERTIFIED, entry.StatusReports[1].Status);
        }
    }
}
