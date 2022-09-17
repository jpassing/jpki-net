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

using Jpki.Format.Ber;
using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Jpki.Security.Cryptography
{
    internal static class EcdsaSignatureFormat
    {
        private static uint SizeOfIeeeP1363Point(uint keySizeInBits)
        {
            return (keySizeInBits + 7u) / 8u;
        }

        public static byte[] Convert(
            byte[] signature,
            DSASignatureFormat sourceFormat,
            DSASignatureFormat targetFormat,
            ushort keySizeInBits)
        {
            //
            // ASN.1 signatures use the following format:
            //
            // Ecdsa-Sig-Value ::=  SEQUENCE  {
            //      r     INTEGER,
            //      s     INTEGER  }
            // }
            //
            // In contrast, IEEE-P1363 is simply:
            //
            //      r || s
            //
            // Note that r and s can have leading zeros. ASN.1/BER
            // trims these zeros, but in IEEE-P1363 they must be
            // maintained.
            //

            if (sourceFormat == targetFormat)
            {
                return signature;
            }
            else if (targetFormat == DSASignatureFormat.Rfc3279DerSequence)
            {
                //
                // Convert IEEE-P1363 to a DER-encoded ASN.1 sequence.
                //
                Debug.Assert(sourceFormat == DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                Debug.Assert((signature.Length % 2) == 0);

                var sizeOfPointInBytes = (uint)signature.Length / 2;

                Debug.Assert(sizeOfPointInBytes == SizeOfIeeeP1363Point(keySizeInBits));

                //
                // Allocate a buffer that can hold the points, plus the BER
                // encoding overhead.
                //
                var sequenceLength =
                    BerDataItem.SizeOfInteger(signature, 0, sizeOfPointInBytes, true) +
                    BerDataItem.SizeOfInteger(signature, sizeOfPointInBytes, sizeOfPointInBytes, true);
                var buffer = new byte[BerDataItem.SizeOfSequence(sequenceLength)];

                Debug.Assert(buffer.Length > signature.Length);

                var item = new BerDataItem(buffer)
                    .WriteSequenceStart(sequenceLength)
                    .WriteInteger(signature, 0, sizeOfPointInBytes, true)
                    .WriteInteger(signature, sizeOfPointInBytes, sizeOfPointInBytes, true);
                Debug.Assert(item.Offset == buffer.Length);
                return buffer;
            }
            else if (targetFormat == DSASignatureFormat.IeeeP1363FixedFieldConcatenation)
            {
                //
                // Convert DER-encoded ASN.1 sequence to IEEE-P1363.
                //
                new BerDataItem(signature)
                    .ReadSequenceStart(out var _)
                    .ReadInteger(out var r, out var _)
                    .ReadInteger(out var s, out var _);

                var pointSize = SizeOfIeeeP1363Point(keySizeInBits);
                var ieeeSignature = new byte[2 * pointSize];

                Array.Copy(r, 0, ieeeSignature, pointSize - r.Length, r.Length);
                Array.Copy(s, 0, ieeeSignature, 2 * pointSize - s.Length, s.Length);

                return ieeeSignature;
            }
            else
            {
                throw new ArgumentException("The target format is not supported");
            }
        }
    }
}
