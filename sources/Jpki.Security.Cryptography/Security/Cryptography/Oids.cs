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

using System.Security.Cryptography;

namespace Jpki.Security.Cryptography
{
    internal static class Oids
    {
        public static readonly Oid BasicConstraints = new Oid("2.5.29.19");
        public static readonly Oid ECC = new Oid("1.2.840.10045.2.1");
        public static readonly Oid RSAES_PKCS1_v1_5 = new Oid("1.2.840.113549.1.1.1");

        public static readonly Oid FidoGenCeAaguid = new Oid("1.3.6.1.4.1.45724.1.1.4");

        /// <summary>
        /// FIDO U2F certificate transports extension,
        /// specifies the transports supported by the authenticator
        /// </summary>
        public static readonly Oid FidoU2fTransports = new Oid("1.3.6.1.4.1.45724.2.1.1");
    }
}
