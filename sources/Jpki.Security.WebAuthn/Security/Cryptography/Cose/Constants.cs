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

using System;

namespace Jpki.Security.Cryptography.Cose
{
    /// <summary>
    /// Key type, see
    /// https://www.iana.org/assignments/cose/cose.xhtml#key-type
    /// </summary>
    public enum CoseKeyType : uint
    {
        EC2 = 2,
        RSA = 3,
    }

    /// <summary>
    /// Hash Algorithms, see
    /// https://www.iana.org/assignments/cose/cose.xhtml#algorithms
    /// </summary>
    [Flags]
    public enum CoseHashAlgorithm : int
    {
        SHA_256 = -16,
        SHA_512 = -44,
        SHA_384 = -43,
    }

    /// <summary>
    /// Signatue Algorithms, see
    /// https://www.iana.org/assignments/cose/cose.xhtml#algorithms
    /// </summary>
    [Flags]
    public enum CoseSignatureAlgorithm : int
    {
        RS512 = -259,
        RS384 = -258,
        RS256 = -257,

        PS512 = -39,
        PS384 = -38,
        PS256 = -37,

        ES256 = -7,
        ES512 = -36,
        ES384 = -35,
    }

    /// <summary>
    /// Elliptic curves, see
    /// https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
    /// </summary>
    public enum CoseEllipticCurves : uint
    {
        P256 = 1,
        P384 = 2,
        P521 = 3,
    }
}
