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
using System.Diagnostics;

namespace Jpki.Format.Ber
{
    internal enum DerTag : byte
    {
        Boolean = 0x01,
        Integer = 0x02,
        BitString = 0x03,
        OctetString = 0x04,
        Null = 0x05,
        ObjectId = 0x06,
        Sequence = 0x30,

        //
        // Unsupported tags:
        //   UTF8String = 0x0C,
        //   BMPString = 0x0E,
        //   PrintableString = 0x13,
        //   TeletexString = 0x14,
        //   IA5String = 0x16,
        //   Set = 0x31
        //
    }

    /// <summary>
    /// A BER encoded data item.
    /// 
    /// NB. This is an incomplete implementation that only 
    /// supports a subset of tags.
    /// 
    /// For details on ASN.1 encoding, see
    /// https://www.oss.com/asn1/resources/books-whitepapers-pubs/larmouth-asn1-book.pdf
    /// </summary>
    internal struct BerDataItem
    {
        private const uint TagLength = 1;

        public readonly DerTag Tag;
        public readonly uint Offset;
        public readonly uint Length;

        private readonly byte[] data;

        private void ThrowIfTagTypeIsNot(DerTag tag)
        {
            if (this.Tag != tag)
            {
                throw new MalformedBerDataItemException(
                    $"Expected data item of type {tag}, but " +
                    $"current data item is of type {this.Tag}");
            }
        }
        private static bool IsHighestBitSet(byte v)
        {
            return (v & 0x80) != 0;
        }

        private BerDataItem Seek(uint offsetDelta)
        {
            Debug.Assert(offsetDelta <= this.Length);

            return new BerDataItem(
                this.data,
                this.Offset + offsetDelta,
                this.Length - offsetDelta);
        }

        /// <summary>
        /// Decode the length portion of the TLV triplet.
        /// </summary>
        private uint DecodeLength(out uint length)
        {
            if (this.Offset + 1 >= this.data.Length)
            {
                throw new MalformedBerDataItemException(
                    "The TLV triplet is incomplete");
            }

            if ((this.data[this.Offset + 1] & 0x80) == 0)
            {
                //
                // Short form encoding (for lengths <= 127).
                //
                length = this.data[this.Offset + 1];
                return TagLength + 1;
            }
            else if (this.data[this.Offset + 1] == 0x80)
            {
                //
                // Indefinite form encoding.
                //
                throw new NotImplementedException(
                    "Indefinite form-encoding is not supported");
            }
            else
            {
                //
                // Long-form encoding.
                //
                var lengthOfLength = (this.data[this.Offset + 1] & 0x7F);

                //
                // The length could be any value, but we only allow 1..4.
                //

                if (lengthOfLength > 4)
                {
                    throw new OverflowException("The length of the data item exceeds 4 bytes");
                }
                else if (this.data[this.Offset + 1] == 0xFF)
                {
                    throw new MalformedBerDataItemException("The length of the data item is invalid");
                }

                //
                // Pad to 4-bytes and decode it using BigEndian.
                //

                var lengthBytes = new byte[4];
                Array.Copy(
                    this.data,
                    this.Offset + 2,
                    lengthBytes,
                    lengthBytes.Length - lengthOfLength,
                    lengthOfLength);

                length = (uint)(
                    (lengthBytes[0] << 24) |
                    (lengthBytes[1] << 16) |
                    (lengthBytes[2] << 8) |
                    (lengthBytes[3] << 0));

                return TagLength + 1 + (uint)lengthOfLength;
            }
        }

        private void ThrowIfBufferCannotFit(uint bytesRequired)
        {
            if (this.Offset + bytesRequired > this.data.Length)
            {
                throw new OverflowException(
                    "The buffer is too small to fit the encoded data");
            }
        }

        private uint EncodeTagAndLength(DerTag tag, uint length)
        {
            ThrowIfBufferCannotFit(SizeOf(tag, length));

            if (length <= 127)
            {
                //
                // Short form encoding (for lengths <= 127).
                //
                ThrowIfBufferCannotFit(2 + length);
                this.data[this.Offset] = (byte)tag;
                this.data[this.Offset + 1] = (byte)length;
                return TagLength + 1;
            }
            else if (length <= ushort.MaxValue)
            {
                //
                // Long-form encoding (2 byte).
                //
                this.data[this.Offset] = (byte)tag;
                this.data[this.Offset + 1] = 0x82;
                this.data[this.Offset + 2] = (byte)((length & 0xFF00) >> 8);
                this.data[this.Offset + 3] = (byte)(length & 0xFF);
                return TagLength + 1 + 2;
            }
            else
            {
                //
                // Long-form encoding (4 byte).
                //
                this.data[this.Offset] = (byte)tag;
                this.data[this.Offset + 1] = 0x84;
                this.data[this.Offset + 2] = (byte)((length & 0xFF000000) >> 24);
                this.data[this.Offset + 3] = (byte)((length & 0xFF0000) >> 16);
                this.data[this.Offset + 4] = (byte)((length & 0xFF00) >> 8);
                this.data[this.Offset + 5] = (byte)(length & 0xFF);
                return TagLength + 1 + 4;
            }
        }

        private static uint SizeOf(DerTag tag, uint length)
        {
            Debug.Assert(Enum.IsDefined(typeof(DerTag), tag));

            if (length <= 127)
            {
                //
                // Short form encoding (for lengths <= 127).
                //
                return TagLength + 1 + length;
            }
            else if (length <= ushort.MaxValue)
            {
                //
                // Long-form encoding (2 byte).
                //
                return TagLength + 1 + 2 + length;
            }
            else
            {
                //
                // Long-form encoding (4 byte).
                //
                return TagLength + 1 + 4 + length;
            }
        }

        //---------------------------------------------------------------------
        // Publics.
        //---------------------------------------------------------------------

        /// <summary>
        /// True if the item cane be read, false if we're
        /// beyond the end of the last readable item.
        /// </summary>
        public bool CanRead => this.Length > 0;

        public BerDataItem(byte[] data, uint offset, uint length)
        {
            this.data = data;
            this.Offset = offset;
            this.Length = length;

            Debug.Assert(offset + length <= data.Length);

            if (length > 0)
            {
                //
                // The high-order 3 bits contain the major type.
                //
                this.Tag = (DerTag)data[offset];
            }
            else
            {
                //
                // We're past the end.
                //
                this.Tag = (DerTag)0;

                Debug.Assert(!this.CanRead);
            }
        }

        public BerDataItem(byte[] buffer)
            : this(buffer, 0, (uint)buffer.Length)
        {
        }

        //---------------------------------------------------------------------
        // Null.
        //
        // The NULL value is encoded into a TLV triplet that begins with
        // a Tag value of 0x05, a Length of 0x00, and no Value.
        //
        // T  L  V
        // -- -- ----
        // 05 00 empty
        //
        //---------------------------------------------------------------------

        public static uint SizeOfNull()
        {
            return SizeOf(DerTag.Null, 0);
        }

        public BerDataItem ReadNull()
        {

            ThrowIfTagTypeIsNot(DerTag.Null);

            var bytesConsumed = DecodeLength(out var valueLength);
            Debug.Assert(valueLength == 0);

            return Seek(bytesConsumed);
        }

        public BerDataItem WriteNull()
        {
            var bytesEncoded = EncodeTagAndLength(DerTag.Null, 0);
            return Seek(bytesEncoded);
        }

        //---------------------------------------------------------------------
        // Boolean.
        //
        // A Boolean value can be TRUE or FALSE. FALSE is encoded as a TLV
        // triplet in which the Value field is zero (0).
        //
        //        T  L  V
        //        -- -- --
        // true:  01 01 FF
        // false: 01 01 00
        //
        // NB. BER allows any non-zero value as true.
        //
        //---------------------------------------------------------------------

        public static uint SizeOfBoolean()
        {
            return SizeOf(DerTag.Boolean, 1);
        }

        public BerDataItem ReadBoolean(out bool value)
        {

            ThrowIfTagTypeIsNot(DerTag.Boolean);

            var bytesConsumed = DecodeLength(out var valueLength);
            Debug.Assert(valueLength == 1);

            value = this.data[this.Offset + bytesConsumed] != 0;
            bytesConsumed += valueLength;

            return Seek(bytesConsumed);
        }

        public BerDataItem WriteBoolean(bool value)
        {
            var bytesEncoded = EncodeTagAndLength(DerTag.Boolean, 1);
            this.data[this.Offset + bytesEncoded] = value ? (byte)0xFF : (byte)0x00;
            bytesEncoded++;

            return Seek(bytesEncoded);
        }

        //---------------------------------------------------------------------
        // Integer.
        //
        //  The Value field of the TLV triplet contains the encoded integer
        //  if it is positive, or its two's complement if it is negative.
        //
        //  If the integer is positive but the high order bit is set to 1,
        //  a leading 0x00 is added to the content to indicate that the
        //  number is not negative. 
        //
        //       T  L  V
        //       -- -- --
        //   72: 02 01 48
        //  127: 02 01 7F
        // -128: 02 01 80
        //  128: 02 02 0080
        //
        //---------------------------------------------------------------------

        public static uint SizeOfInteger(byte[] value, uint offset, uint length, bool positive)
        {
            value.ExpectNotNullOrZeroSized(nameof(value));

            while (value[offset] == 0x00)
            {
                offset++;
                length--;
            }

            if (positive && IsHighestBitSet(value[offset]))
            {
                return SizeOf(DerTag.Integer, length + 1);
            }
            else
            {
                return SizeOf(DerTag.Integer, length);
            }
        }

        public static uint SizeOfInteger(byte[] value, bool positive)
        {
            value.ExpectNotNullOrZeroSized(nameof(value));
            return SizeOfInteger(value, 0, (uint)value.Length, positive);
        }

        public BerDataItem ReadInteger(out byte[] value, out bool positive)
        {
            ThrowIfTagTypeIsNot(DerTag.Integer);

            var bytesConsumed = DecodeLength(out var valueLength);

            if (valueLength >= 2 &&
                this.data[this.Offset + bytesConsumed] == 0 &&
                IsHighestBitSet(this.data[this.Offset + bytesConsumed + 1]))
            {
                //
                // First byte is padding.
                //
                positive = true;
                bytesConsumed++;
                valueLength--;
            }
            else
            {
                positive = !IsHighestBitSet(this.data[this.Offset + bytesConsumed]);
            }

            value = new byte[valueLength];
            Array.Copy(this.data, this.Offset + bytesConsumed, value, 0, valueLength);
            bytesConsumed += valueLength;

            return Seek(bytesConsumed);
        }

        public BerDataItem WriteInteger(byte[] value, uint offset, uint length, bool positive)
        {
            value.ExpectNotNullOrZeroSized(nameof(value));

            while (value[offset] == 0x00)
            {
                offset++;
                length--;
            }

            var paddingLength = (positive && IsHighestBitSet(value[offset])) ? 1u : 0;

            var bytesEncoded = EncodeTagAndLength(
                DerTag.Integer,
                length + paddingLength);

            Array.Copy(
                value,
                offset,
                this.data,
                this.Offset + bytesEncoded + paddingLength,
                length);

            bytesEncoded += length + paddingLength;
            return Seek(bytesEncoded);
        }

        public BerDataItem WriteInteger(byte[] value, bool positive)
        {
            value.ExpectNotNullOrZeroSized(nameof(value));
            return WriteInteger(value, 0, (uint)value.Length, positive);
        }

        //---------------------------------------------------------------------
        // Sequence.
        //---------------------------------------------------------------------

        public static uint SizeOfSequence(uint lengthInBytes)
        {
            return SizeOf(DerTag.Sequence, lengthInBytes);
        }

        public BerDataItem ReadSequenceStart(out uint length)
        {
            ThrowIfTagTypeIsNot(DerTag.Sequence);

            var bytesConsumed = DecodeLength(out length);
            return Seek(bytesConsumed);
        }

        public BerDataItem WriteSequenceStart(uint length)
        {
            var bytesEncoded = EncodeTagAndLength(DerTag.Sequence, length);
            return Seek(bytesEncoded);
        }
    }
}
