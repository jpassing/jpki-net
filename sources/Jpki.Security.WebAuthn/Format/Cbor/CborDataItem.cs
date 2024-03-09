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
using System.Text;

namespace Jpki.Format.Cbor
{
    /// <summary>
    /// Major type as defined in RFC 8949, 3.1.
    /// </summary>
    internal enum CborMajorType : byte
    {
        UnsignedInteger = 0,
        NegativeInteger = 1,
        ByteString = 2,
        TextString = 3,
        Array = 4,
        Map = 5,
        TaggedItem = 6,
        FloatingPointOrSimpleValue = 7
    }

    /// <summary>
    /// Simple value as defined in RFC 8949, 3.3.
    /// </summary>
    internal enum SimpleValue
    {
        False = 20,
        True = 21,
        Null = 22,
        Undefined = 23,
        Stop = 31
    }

    /// <summary>
    /// Tags as defined in RFC 8949, 3.4.
    /// </summary>
    internal enum Tag
    {
        DateTimeString = 0,
        EpochBasedDateTime = 1,
        UnsignedBigNum = 2,
        NegativeBigNum = 3,
        DecimalFraction = 4,
        Bigfloat = 5,
        ExpectedConversionToBase64Url = 21,
        ExpectedConversionToBase64 = 22,
        ExpectedConversionToBase16 = 23,
        CborDataItem = 24,
        Uri = 32,
        Base64Url = 33,
        Base64 = 34,
        MimeMessage = 36,
        SelfDescribedCbor = 55799
    }

    /// <summary>
    /// A single CBOR data item.
    /// </summary>
    internal struct CborDataItem
    {
        private const uint HeaderLength = 1;

        public readonly CborMajorType MajorType;
        public readonly byte AdditionalInformation;
        public readonly uint Offset;
        public readonly uint Length;

        private readonly byte[] data;

        private void ThrowIfMajorTypeIsNot(CborMajorType type)
        {
            if (this.MajorType != type)
            {
                throw new MalformedCborDataItemException(
                    $"Expected data item of type {type}, but " +
                    $"current data item is of type {this.MajorType}");
            }
        }

        private CborDataItem Seek(uint offsetDelta)
        {
            Debug.Assert(offsetDelta <= this.Length);

            return new CborDataItem(
                this.data,
                this.Offset + offsetDelta,
                this.Length - offsetDelta);
        }

        private uint DecodeArgument(out ulong value)
        {
            if (this.AdditionalInformation < 24)
            {
                //
                // Less than 24: The argument's value is the value of the
                // additional information.
                //
                value = this.AdditionalInformation;
                return HeaderLength;
            }

            switch (this.AdditionalInformation)
            {
                case 24:
                    value = this.data[this.Offset + 1];
                    return HeaderLength + sizeof(byte);

                case 25:
                    value = (ulong)(
                        (this.data[this.Offset + 1] << 8) |
                        (this.data[this.Offset + 2] << 0));
                    return HeaderLength + sizeof(ushort);

                case 26:
                    value = (ulong)(
                        (this.data[this.Offset + 1] << 24) |
                        (this.data[this.Offset + 2] << 16) |
                        (this.data[this.Offset + 3] << 8) |
                        (this.data[this.Offset + 4] << 0));
                    return HeaderLength + sizeof(uint);

                case 27:
                    value = (ulong)(
                        ((ulong)this.data[this.Offset + 1] << 56) |
                        ((ulong)this.data[this.Offset + 2] << 48) |
                        ((ulong)this.data[this.Offset + 3] << 40) |
                        ((ulong)this.data[this.Offset + 4] << 32) |
                        ((ulong)this.data[this.Offset + 5] << 24) |
                        ((ulong)this.data[this.Offset + 6] << 16) |
                        ((ulong)this.data[this.Offset + 7] << 8) |
                        ((ulong)this.data[this.Offset + 8] << 0));
                    return HeaderLength + sizeof(ulong);
            }

            throw new MalformedCborDataItemException($"Buffer contains malformed CBOR: {this}");
        }

        //---------------------------------------------------------------------
        // Publics.
        //---------------------------------------------------------------------

        /// <summary>
        /// True if the item cane be read, false if we're
        /// beyond the end of the last readable item.
        /// </summary>
        public bool CanRead => this.Length > 0;

        public CborDataItem(byte[] data, uint offset, uint length)
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
                this.MajorType = (CborMajorType)(data[offset] >> 5);

                //
                // The the low-order 5 bits contain "additional information".
                //
                this.AdditionalInformation = (byte)(data[offset] & 0x1f);
            }
            else
            {
                //
                // We're past the end.
                //
                this.MajorType = CborMajorType.FloatingPointOrSimpleValue;
                this.AdditionalInformation = 31; // Break.

                Debug.Assert(this.IsBreak);
                Debug.Assert(!this.CanRead);
            }
        }

        public CborDataItem(byte[] buffer)
            : this(buffer, 0, (uint)buffer.Length)
        {
        }


        public CborDataItem ReadUnsignedInteger(out ulong value)
        {
            // 
            // An unsigned integer in the range 0..264-1 inclusive. The value of
            // the encoded item is the argument itself. For example, the integer
            // 10 is denoted as the one byte 0b000_01010 (major type 0, additional
            // information 10). The integer 500 would be 0b000_11001 (major type 0,
            // additional information 25) followed by the two bytes 0x01f4, which
            // is 500 in decimal.
            // 
            ThrowIfMajorTypeIsNot(CborMajorType.UnsignedInteger);

            var bytesConsumed = DecodeArgument(out value);

            return Seek(bytesConsumed);
        }

        public CborDataItem ReadNegativeInteger(out long value)
        {
            //
            // A negative integer in the range -264..-1 inclusive. The value of the
            // item is -1 minus the argument. For example, the integer -500 would
            // be 0b001_11001 (major type 1, additional information 25) followed by
            // the two bytes 0x01f3, which is 499 in decimal.
            //
            ThrowIfMajorTypeIsNot(CborMajorType.NegativeInteger);

            var lengthThruArgument = DecodeArgument(out var argument);
            if (argument > long.MaxValue)
            {
                throw new OverflowException("Negative value is too large to fit Int64");
            }

            value = -1L - (long)argument;
            return Seek(lengthThruArgument);
        }

        public CborDataItem ReadByteString(out byte[] value)
        {
            //
            // A byte string. The number of bytes in the string is equal to the argument. 
            // For example, a byte string whose length is 5 would have an initial byte 
            // of 0b010_00101 (major type 2, additional information 5 for the length), 
            // followed by 5 bytes of binary content. A byte string whose length is 
            // 500 would have 3 initial bytes of 0b010_11001 (major type 2, additional 
            // information 25 to indicate a two-byte length) followed by the two bytes 
            // 0x01f4 for a length of 500, followed by 500 bytes of binary content.
            //
            ThrowIfMajorTypeIsNot(CborMajorType.ByteString);

            if (this.AdditionalInformation == 31)
            {
                throw new UnsupportedCborDataItemException(
                    "Infinite-sized text strings are not supported");
            }

            var lengthThruArgument = DecodeArgument(out var stringLength);
            if (stringLength > int.MaxValue)
            {
                throw new OverflowException("String exceeds maximum length");
            }

            value = new byte[stringLength];
            Array.Copy(this.data, this.Offset + lengthThruArgument, value, 0, value.Length);

            return Seek(lengthThruArgument + (uint)stringLength);
        }

        public CborDataItem ReadTextString(out string value)
        {
            //
            // A text string (Section 2) encoded as UTF-8 [RFC3629]. The number of bytes 
            // in the string is equal to the argument. A string containing an invalid 
            // UTF-8 sequence is well-formed but invalid (Section 1.2). This type is 
            // provided for systems that need to interpret or display human-readable text, 
            // and allows the differentiation between unstructured bytes and text 
            // that has a specified repertoire (that of Unicode) and encoding (UTF-8). 
            // In contrast to formats such as JSON, the Unicode characters in this 
            // type are never escaped. Thus, a newline character (U+000A) is always 
            // represented in a string as the byte 0x0a, and never as the bytes 0x5c6e 
            // (the characters "\" and "n") nor as 0x5c7530303061
            // (the characters "\", "u", "0", "0", "0", and "a").
            //
            ThrowIfMajorTypeIsNot(CborMajorType.TextString);

            if (this.AdditionalInformation == 31)
            {
                throw new UnsupportedCborDataItemException(
                    "Infinite-sized text strings are not supported");
            }

            var lengthThruArgument = DecodeArgument(out var stringLength);
            if (stringLength > int.MaxValue)
            {
                throw new OverflowException("String exceeds maximum length");
            }

            value = Encoding.UTF8.GetString(
                this.data,
                (int)(this.Offset + lengthThruArgument),
                (int)stringLength);

            return Seek(lengthThruArgument + (uint)stringLength);
        }

        public CborDataItem ReadArrayStart(out uint? itemCount)
        {
            //
            // An array of data items. In other formats, arrays are also called lists, 
            // sequences, or tuples (a "CBOR sequence" is something slightly different, 
            // though [RFC8742]). The argument is the number of data items in the array. 
            // Items in an array do not need to all be of the same type. For example, 
            // an array that contains 10 items of any type would have an initial byte 
            // of 0b100_01010 (major type 4, additional information 10 for the length) 
            // followed by the 10 remaining items.
            //
            ThrowIfMajorTypeIsNot(CborMajorType.Array);

            if (this.AdditionalInformation == 31)
            {
                //
                // Indefinite length.
                //
                itemCount = null;
                return Seek(HeaderLength);
            }
            else
            {
                var lengthThruArgument = DecodeArgument(out var argument);
                if (argument > uint.MaxValue)
                {
                    throw new OverflowException("Array exceeds maximum length");
                }

                itemCount = (uint)argument;
                return Seek(lengthThruArgument);
            }
        }

        public CborDataItem ReadMapStart(out uint? pairCount)
        {
            //
            // A map of pairs of data items. Maps are also called tables, dictionaries, 
            // hashes, or objects (in JSON). A map is comprised of pairs of data items, 
            // each pair consisting of a key that is immediately followed by a value. 
            // The argument is the number of pairs of data items in the map. For example, 
            // a map that contains 9 pairs would have an initial byte of 0b101_01001 
            // (major type 5, additional information 9 for the number of pairs) followed 
            // by the 18 remaining items. The first item is the first key, the second 
            // item is the first value, the third item is the second key, and so on. 
            // Because items in a map come in pairs, their total number is always even: 
            // a map that contains an odd number of items (no value data present after 
            // the last key data item) is not well-formed. A map that has duplicate 
            // keys may be well-formed, but it is not valid, and thus it causes 
            // indeterminate decoding
            //
            ThrowIfMajorTypeIsNot(CborMajorType.Map);

            if (this.AdditionalInformation == 31)
            {
                //
                // Indefinite length.
                //
                pairCount = null;
                return Seek(HeaderLength);
            }
            else
            {
                var lengthThruArgument = DecodeArgument(out var argument);
                if (argument > uint.MaxValue)
                {
                    throw new OverflowException("Map exceeds maximum length");
                }

                pairCount = (uint)argument;
                return Seek(lengthThruArgument);
            }
        }

        public CborDataItem ReadTaggedItemStart(out Tag tag)
        {
            //
            // A tagged data item ("tag") whose tag number, an integer in the range
            // 0..264-1 inclusive, is the argument and whose enclosed data item (tag 
            // content) is the single encoded data item that follows the head.
            // 
            ThrowIfMajorTypeIsNot(CborMajorType.TaggedItem);

            var lengthThruArgument = DecodeArgument(out var rawTag);

            tag = (Tag)rawTag;
            Debug.Assert(Enum.IsDefined(typeof(Tag), tag));

            return Seek(lengthThruArgument);
        }

        public bool IsFloatingPoint
            => this.MajorType == CborMajorType.FloatingPointOrSimpleValue &&
               (this.AdditionalInformation == 25 ||
                this.AdditionalInformation == 26 ||
                this.AdditionalInformation == 27);

        public bool IsSimpleValue
            => this.MajorType == CborMajorType.FloatingPointOrSimpleValue &&
               this.AdditionalInformation <= 24;

        public bool IsBreak
            => this.MajorType == CborMajorType.FloatingPointOrSimpleValue &&
               this.AdditionalInformation == 31;


        public CborDataItem ReadSimpleValue(out SimpleValue value)
        {
            ThrowIfMajorTypeIsNot(CborMajorType.FloatingPointOrSimpleValue);

            if (this.AdditionalInformation < 24 || this.AdditionalInformation == 31)
            {
                //
                // Less than 24: The argument's value is the value of the
                // additional information.
                //
                // 31 is Stop.
                //
                value = (SimpleValue)this.AdditionalInformation;
                return Seek(HeaderLength);
            }
            else if (this.AdditionalInformation == 24)
            {
                //
                // Simple value is in the next byte.
                //
                value = (SimpleValue)this.data[this.Offset + 1];

                return Seek(HeaderLength + sizeof(byte));
            }
            else
            {
                throw new MalformedCborDataItemException($"Item is not a simple value: {this}");
            }
        }

        public CborDataItem ReadFloatingPoint(out double value)
        {
            ThrowIfMajorTypeIsNot(CborMajorType.FloatingPointOrSimpleValue);
            value = 0.0;
            throw new UnsupportedCborDataItemException(
                "Floating point data items are not supported");
        }

        public CborDataItem Skip()
        {
            switch (this.MajorType)
            {
                case CborMajorType.UnsignedInteger:
                    return ReadUnsignedInteger(out var _);

                case CborMajorType.NegativeInteger:
                    return ReadNegativeInteger(out var _);

                case CborMajorType.ByteString:
                    return ReadByteString(out var _);

                case CborMajorType.TextString:
                    return ReadTextString(out var _);

                case CborMajorType.Array:
                case CborMajorType.Map:
                case CborMajorType.TaggedItem:
                    throw new UnsupportedCborDataItemException(
                        "Skipping complex types is not supported");

                case CborMajorType.FloatingPointOrSimpleValue:
                    if (this.IsSimpleValue || this.IsBreak)
                    {
                        return ReadSimpleValue(out var _);
                    }

                    break;

                default:
                    break;
            }

            throw new MalformedCborDataItemException(
                $"Unrecognized data item {this}");
        }

        public override string ToString()
        {
            return $"MT={this.MajorType}, AI={this.AdditionalInformation}";
        }
    }
}
