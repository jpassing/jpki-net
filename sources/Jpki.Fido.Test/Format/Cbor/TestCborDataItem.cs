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

using Jpki.Format.Cbor;
using NUnit.Framework;

namespace Jpki.Test.Format.Cbor
{
    [TestFixture]
    public class TestCborDataItem
    {
        //---------------------------------------------------------------------
        // UnsignedInteger.
        //---------------------------------------------------------------------

        [Test]
        public void UnsignedIntegerInArgument(
            [Values(0, 1, 23)] byte value)
        {
            var data = new byte[] { value };

            var item = new CborDataItem(data);

            AssertThat.AreEqual(CborMajorType.UnsignedInteger, item.MajorType);
            var nextItem = item.ReadUnsignedInteger(out var decoded);

            AssertThat.AreEqual(value, decoded);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void UnsignedIntegerInSingleByte(
            [Values(24, 25, 100)] byte value)
        {
            var data = new byte[] { 0x18, value };

            var item = new CborDataItem(data);

            AssertThat.AreEqual(CborMajorType.UnsignedInteger, item.MajorType);
            var nextItem = item.ReadUnsignedInteger(out var decoded);

            AssertThat.AreEqual(value, decoded);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void UnsignedIntegerInTwoBytes()
        {
            var data = new byte[] { 0x19, 0x03, 0xe8 };

            var item = new CborDataItem(data);

            AssertThat.AreEqual(CborMajorType.UnsignedInteger, item.MajorType);
            var nextItem = item.ReadUnsignedInteger(out var decoded);

            AssertThat.AreEqual(1000, decoded);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void UnsignedIntegerInFourBytes()
        {
            var data = new byte[] { 0x1a, 0x00, 0x0f, 0x42, 0x40 };

            var item = new CborDataItem(data);

            AssertThat.AreEqual(CborMajorType.UnsignedInteger, item.MajorType);
            var nextItem = item.ReadUnsignedInteger(out var decoded);

            AssertThat.AreEqual(1000000, decoded);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void UnsignedIntegerInEightBytes()
        {
            var data = new byte[] { 0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00 };

            var item = new CborDataItem(data);

            AssertThat.AreEqual(CborMajorType.UnsignedInteger, item.MajorType);
            var nextItem = item.ReadUnsignedInteger(out var decoded);

            AssertThat.AreEqual(1000000000000, decoded);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void UnsignedIntegerMax()
        {
            var data = new byte[] { 0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

            var item = new CborDataItem(data);

            AssertThat.AreEqual(CborMajorType.UnsignedInteger, item.MajorType);
            var nextItem = item.ReadUnsignedInteger(out var decoded);

            AssertThat.AreEqual(ulong.MaxValue, decoded);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void SkipUnsignedInteger()
        {
            var data = new byte[] { 0x18, 1, 0x19, 0x03, 0xe8 };

            new CborDataItem(data)
                .Skip()
                .ReadUnsignedInteger(out var decoded);

            AssertThat.AreEqual(1000, decoded);
        }

        //---------------------------------------------------------------------
        // NegativeInteger.
        //---------------------------------------------------------------------

        [Test]
        public void NegativeIntegerInArgument()
        {
            var data = new byte[] { 0x20 };

            var item = new CborDataItem(data);

            AssertThat.AreEqual(CborMajorType.NegativeInteger, item.MajorType);
            var nextItem = item.ReadNegativeInteger(out var decoded);

            AssertThat.AreEqual(-1, decoded);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void NegativeIntegerInSingleByte()
        {
            var data = new byte[] { 0x38, 0x63 };

            var item = new CborDataItem(data);

            AssertThat.AreEqual(CborMajorType.NegativeInteger, item.MajorType);
            var nextItem = item.ReadNegativeInteger(out var decoded);

            AssertThat.AreEqual(-100, decoded);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void NegativeIntegerInTwoBytes()
        {
            var data = new byte[] { 0x39, 0x03, 0xe7 };

            var item = new CborDataItem(data);

            AssertThat.AreEqual(CborMajorType.NegativeInteger, item.MajorType);
            var nextItem = item.ReadNegativeInteger(out var decoded);

            AssertThat.AreEqual(-1000, decoded);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void NegativeIntegerInFourBytes()
        {
            var data = new byte[] { 0x3a, 0x00, 0x0f, 0x42, 0x3f };

            var item = new CborDataItem(data);

            AssertThat.AreEqual(CborMajorType.NegativeInteger, item.MajorType);
            var nextItem = item.ReadNegativeInteger(out var decoded);

            AssertThat.AreEqual(-1000000, decoded);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void SkipNegativeInteger()
        {
            var data = new byte[] { 0x3a, 0x00, 0x0f, 0x42, 0x3f, 0x38, 0x63 };

            new CborDataItem(data)
                .Skip()
                .ReadNegativeInteger(out var decoded);

            AssertThat.AreEqual(-100, decoded);
        }

        //---------------------------------------------------------------------
        // SimpleValue.
        //---------------------------------------------------------------------

        [Test]
        public void SimpleValueFalse()
        {
            var data = new byte[] { 0xf4 };

            var item = new CborDataItem(data);

            AssertThat.AreEqual(CborMajorType.FloatingPointOrSimpleValue, item.MajorType);
            var nextItem = item.ReadSimpleValue(out var decoded);

            AssertThat.AreEqual(SimpleValue.False, decoded);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void SimpleValueTrue()
        {
            var data = new byte[] { 0xf5 };

            var item = new CborDataItem(data);

            AssertThat.AreEqual(CborMajorType.FloatingPointOrSimpleValue, item.MajorType);
            var nextItem = item.ReadSimpleValue(out var decoded);

            AssertThat.AreEqual(SimpleValue.True, decoded);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void SimpleValueNull()
        {
            var data = new byte[] { 0xf6 };

            var item = new CborDataItem(data);

            AssertThat.AreEqual(CborMajorType.FloatingPointOrSimpleValue, item.MajorType);
            var nextItem = item.ReadSimpleValue(out var decoded);

            AssertThat.AreEqual(SimpleValue.Null, decoded);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void SimpleValueUndefined()
        {
            var data = new byte[] { 0xf7 };

            var item = new CborDataItem(data);

            AssertThat.AreEqual(CborMajorType.FloatingPointOrSimpleValue, item.MajorType);
            var nextItem = item.ReadSimpleValue(out var decoded);

            AssertThat.AreEqual(SimpleValue.Undefined, decoded);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void SimpleValue16()
        {
            var data = new byte[] { 0xf0 };

            var item = new CborDataItem(data);

            AssertThat.AreEqual(CborMajorType.FloatingPointOrSimpleValue, item.MajorType);
            var nextItem = item.ReadSimpleValue(out var decoded);

            AssertThat.AreEqual(16, (int)decoded);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void SimpleValue255()
        {
            var data = new byte[] { 0xf8, 0xff };

            var item = new CborDataItem(data);

            AssertThat.AreEqual(CborMajorType.FloatingPointOrSimpleValue, item.MajorType);
            var nextItem = item.ReadSimpleValue(out var decoded);

            AssertThat.AreEqual(255, (int)decoded);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void SimpleValueBreak()
        {
            var data = new byte[] { 0xff };

            var item = new CborDataItem(data);

            AssertThat.AreEqual(CborMajorType.FloatingPointOrSimpleValue, item.MajorType);
            var nextItem = item.ReadSimpleValue(out var decoded);

            AssertThat.AreEqual(SimpleValue.Stop, decoded);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void SkipSimpleValue()
        {
            var data = new byte[] { 0xf0, 0x38, 0x63 };

            new CborDataItem(data)
                .Skip()
                .ReadNegativeInteger(out var decoded);

            AssertThat.AreEqual(-100, decoded);
        }

        //---------------------------------------------------------------------
        // ByteString.
        //---------------------------------------------------------------------

        [Test]
        public void ByteStringWithZeroLength()
        {
            var data = new byte[] { 0x40 };

            var item = new CborDataItem(data);

            AssertThat.AreEqual(CborMajorType.ByteString, item.MajorType);
            var nextItem = item.ReadByteString(out var decoded);

            AssertThat.AreEqual(0, decoded.Length);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void ByteStringWithInfiniteLength()
        {
            var data = new byte[] { 0x5f };

            var item = new CborDataItem(data);

            AssertThat.AreEqual(CborMajorType.ByteString, item.MajorType);
            AssertThat.Throws<UnsupportedCborDataItemException>(
                () => item.ReadByteString(out var decoded));
        }

        [Test]
        public void ByteStringWithFourBytes()
        {
            var data = new byte[] { 0x44, 0x01, 0x02, 0x03, 0x04 };

            var item = new CborDataItem(data);

            AssertThat.AreEqual(CborMajorType.ByteString, item.MajorType);
            var nextItem = item.ReadByteString(out var decoded);

            AssertThat.AreEqual(4, decoded.Length);
            AssertThat.AreEqual(0x01, decoded[0]);
            AssertThat.AreEqual(0x02, decoded[1]);
            AssertThat.AreEqual(0x03, decoded[2]);
            AssertThat.AreEqual(0x04, decoded[3]);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void SkipByteString()
        {
            var data = new byte[] { 0x44, 0x01, 0x02, 0x03, 0x04, 0x38, 0x63 };

            new CborDataItem(data)
                .Skip()
                .ReadNegativeInteger(out var decoded);

            AssertThat.AreEqual(-100, decoded);
        }

        //---------------------------------------------------------------------
        // TextString.
        //---------------------------------------------------------------------

        [Test]
        public void TextStringWithZeroLength()
        {
            var data = new byte[] { 0x60 };

            var item = new CborDataItem(data);

            AssertThat.AreEqual(CborMajorType.TextString, item.MajorType);
            var nextItem = item.ReadTextString(out var decoded);

            AssertThat.AreEqual(string.Empty, decoded);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void TextStringWithInfiniteLength()
        {
            var data = new byte[] { 0x7f };

            var item = new CborDataItem(data);

            AssertThat.AreEqual(CborMajorType.TextString, item.MajorType);
            AssertThat.Throws<UnsupportedCborDataItemException>(
                () => item.ReadTextString(out var decoded));
        }

        [Test]
        public void TextStringWithSingleChar()
        {
            var data = new byte[] { 0x61, 0x61 };

            var item = new CborDataItem(data);

            AssertThat.AreEqual(CborMajorType.TextString, item.MajorType);
            var nextItem = item.ReadTextString(out var decoded);

            AssertThat.AreEqual("a", decoded);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void TextStringWithFourChars()
        {
            var data = new byte[] { 0x64, 0x49, 0x45, 0x54, 0x46 };

            var item = new CborDataItem(data);

            AssertThat.AreEqual(CborMajorType.TextString, item.MajorType);
            var nextItem = item.ReadTextString(out var decoded);

            AssertThat.AreEqual("IETF", decoded);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void TextStringWithSpecialChar()
        {
            var data = new byte[] { 0x62, 0xc3, 0xbc };

            var item = new CborDataItem(data);

            AssertThat.AreEqual(CborMajorType.TextString, item.MajorType);
            var nextItem = item.ReadTextString(out var decoded);

            AssertThat.AreEqual("\u00fc", decoded);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void SkipTextString()
        {
            var data = new byte[] { 0x62, 0xc3, 0xbc, 0x38, 0x63 };

            new CborDataItem(data)
                .Skip()
                .ReadNegativeInteger(out var decoded);

            AssertThat.AreEqual(-100, decoded);
        }

        //---------------------------------------------------------------------
        // Array.
        //---------------------------------------------------------------------

        [Test]
        public void ArrayWithZeroLength()
        {
            var data = new byte[] { 0x80 };

            var item = new CborDataItem(data);

            AssertThat.AreEqual(CborMajorType.Array, item.MajorType);
            var nextItem = item.ReadArrayStart(out var itemCount);

            AssertThat.AreEqual(0, itemCount);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void ArrayWithThreeUnsignedIntegers()
        {
            var data = new byte[] { 0x83, 0x01, 0x02, 0x03 };

            var item = new CborDataItem(data);

            AssertThat.AreEqual(CborMajorType.Array, item.MajorType);
            item = item.ReadArrayStart(out var itemCount);

            AssertThat.AreEqual(3, itemCount);

            for (int i = 1; i <= 3; i++)
            {
                AssertThat.AreEqual(CborMajorType.UnsignedInteger, item.MajorType);
                item = item.ReadUnsignedInteger(out var decodedItem);

                AssertThat.AreEqual(i, decodedItem);
            }
        }

        [Test]
        public void ArrayWithIndefiniteLength()
        {
            var data = new byte[] { 0x9f, 0x01, 0x02, 0xff };

            var item = new CborDataItem(data);

            AssertThat.AreEqual(CborMajorType.Array, item.MajorType);
            item = item.ReadArrayStart(out var itemCount);

            AssertThat.IsNull(itemCount);

            for (int i = 1; i <= 2; i++)
            {
                AssertThat.AreEqual(CborMajorType.UnsignedInteger, item.MajorType);
                item = item.ReadUnsignedInteger(out var decodedItem);

                AssertThat.AreEqual(i, decodedItem);
            }

            AssertThat.AreEqual(CborMajorType.FloatingPointOrSimpleValue, item.MajorType);
            AssertThat.IsTrue(item.IsBreak);
        }

        [Test]
        public void SkipArray()
        {
            var data = new byte[] { 0x9f, 0x01, 0x02, 0xff };

            AssertThat.Throws<UnsupportedCborDataItemException>(
                () => new CborDataItem(data).Skip());
        }

        //---------------------------------------------------------------------
        // Map.
        //---------------------------------------------------------------------

        [Test]
        public void MapWithZeroLength()
        {
            var data = new byte[] { 0xa0 };

            var item = new CborDataItem(data);

            AssertThat.AreEqual(CborMajorType.Map, item.MajorType);
            var nextItem = item.ReadMapStart(out var itemCount);

            AssertThat.AreEqual(0, itemCount);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void MapWithTwoUnsignedIntegerPairs()
        {
            var data = new byte[] { 0xa2, 0x01, 0x02, 0x03, 0x04 };

            var item = new CborDataItem(data);

            AssertThat.AreEqual(CborMajorType.Map, item.MajorType);
            item = item.ReadMapStart(out var itemCount);

            AssertThat.AreEqual(2, itemCount);

            for (int i = 1; i <= 4; i++)
            {
                AssertThat.AreEqual(CborMajorType.UnsignedInteger, item.MajorType);
                item = item.ReadUnsignedInteger(out var decodedItem);

                AssertThat.AreEqual(i, decodedItem);
            }
        }

        [Test]
        public void MapWithIndefiniteLength()
        {
            var data = new byte[] { 0xbf, 0x01, 0x02, 0xff };

            var item = new CborDataItem(data);

            AssertThat.AreEqual(CborMajorType.Map, item.MajorType);
            item = item.ReadMapStart(out var itemCount);

            AssertThat.IsNull(itemCount);

            for (int i = 1; i <= 2; i++)
            {
                AssertThat.AreEqual(CborMajorType.UnsignedInteger, item.MajorType);
                item = item.ReadUnsignedInteger(out var decodedItem);

                AssertThat.AreEqual(i, decodedItem);
            }

            AssertThat.AreEqual(CborMajorType.FloatingPointOrSimpleValue, item.MajorType);
            AssertThat.IsTrue(item.IsBreak);
        }

        [Test]
        public void SkipMap()
        {
            var data = new byte[] { 0xbf, 0x01, 0x02, 0xff };

            AssertThat.Throws<UnsupportedCborDataItemException>(
                () => new CborDataItem(data).Skip());
        }

        //---------------------------------------------------------------------
        // TaggedItem.
        //---------------------------------------------------------------------

        [Test]
        public void TaggedItemWithUnsignedInteger()
        {
            var data = new byte[] { 0xc1, 0x1a, 0x51, 0x4b, 0x67, 0xb0 };

            var item = new CborDataItem(data);

            AssertThat.AreEqual(CborMajorType.TaggedItem, item.MajorType);
            item = item.ReadTaggedItemStart(out var tag);

            AssertThat.AreEqual(Tag.EpochBasedDateTime, tag);

            AssertThat.AreEqual(CborMajorType.UnsignedInteger, item.MajorType);
            item = item.ReadUnsignedInteger(out var unsignedInt);
            AssertThat.AreEqual(1363896240, unsignedInt);

            AssertThat.IsFalse(item.CanRead);
        }

        [Test]
        public void SkipTaggedItem()
        {
            var data = new byte[] { 0xc1, 0x1a, 0x51, 0x4b, 0x67, 0xb0 };

            AssertThat.Throws<UnsupportedCborDataItemException>(
                () => new CborDataItem(data).Skip());
        }
    }
}
