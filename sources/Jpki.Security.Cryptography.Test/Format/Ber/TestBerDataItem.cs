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
using NUnit.Framework;
using System;
using System.Linq;

namespace Jpki.Test.Format.Ber
{
    [TestFixture]
    public class TestBerDataItem
    {
        //---------------------------------------------------------------------
        // Null.
        //---------------------------------------------------------------------

        [Test]
        public void ReadNull()
        {
            var data = new byte[] { 0x05, 0x00 };

            var item = new BerDataItem(data);

            AssertThat.AreEqual(DerTag.Null, item.Tag);
            var nextItem = item.ReadNull();

            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void WriteNull()
        {
            var buffer = new byte[BerDataItem.SizeOfNull()];

            var item = new BerDataItem(buffer)
                .WriteNull();

            AssertThat.AreEqual(
                new byte[] { 0x05, 0x00 },
                buffer);
            AssertThat.AreEqual(buffer.Length, item.Offset);
        }

        //---------------------------------------------------------------------
        // Boolean.
        //---------------------------------------------------------------------

        [Test]
        public void ReadBooleanFalse()
        {
            var data = new byte[] { 0x01, 0x01, 0x00 };

            var item = new BerDataItem(data);

            AssertThat.AreEqual(DerTag.Boolean, item.Tag);
            var nextItem = item.ReadBoolean(out var decoded);

            AssertThat.IsFalse(decoded);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void ReadBooleanTrue(
            [Values(1, 0x10, 0xFF)] byte value)
        {
            var data = new byte[] { 0x01, 0x01, value };

            var item = new BerDataItem(data);

            AssertThat.AreEqual(DerTag.Boolean, item.Tag);
            var nextItem = item.ReadBoolean(out var decoded);

            AssertThat.IsTrue(decoded);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void ReadBooleanTrueWithLengthInLongForm1()
        {
            var data = new byte[] { 0x01, 0x81, 0x01, 0xFF };

            var item = new BerDataItem(data);

            AssertThat.AreEqual(DerTag.Boolean, item.Tag);
            var nextItem = item.ReadBoolean(out var decoded);

            AssertThat.IsTrue(decoded);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void ReadBooleanTrueWithLengthInLongForm2()
        {
            var data = new byte[] { 0x01, 0x82, 0x00, 0x01, 0xFF };

            var item = new BerDataItem(data);

            AssertThat.AreEqual(DerTag.Boolean, item.Tag);
            var nextItem = item.ReadBoolean(out var decoded);

            AssertThat.IsTrue(decoded);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void ReadBooleanTrueWithLengthInLongForm3()
        {
            var data = new byte[] { 0x01, 0x83, 0x00, 0x00, 0x01, 0xFF };

            var item = new BerDataItem(data);

            AssertThat.AreEqual(DerTag.Boolean, item.Tag);
            var nextItem = item.ReadBoolean(out var decoded);

            AssertThat.IsTrue(decoded);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void ReadBooleanTrueWithLengthInLongForm4()
        {
            var data = new byte[] { 0x01, 0x84, 0x00, 0x00, 0x00, 0x01, 0xFF };

            var item = new BerDataItem(data);

            AssertThat.AreEqual(DerTag.Boolean, item.Tag);
            var nextItem = item.ReadBoolean(out var decoded);

            AssertThat.IsTrue(decoded);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void ReadBooleanTrueWithLengthInIndefiniteFormThrowsException()
        {
            var data = new byte[] { 0x01, 0x80, 0x00 };

            var item = new BerDataItem(data);

            AssertThat.AreEqual(DerTag.Boolean, item.Tag);

            AssertThat.Throws<NotImplementedException>(
                () => item.ReadBoolean(out var decoded));
        }

        [Test]
        public void WriteBooleanTrue()
        {
            var buffer = new byte[BerDataItem.SizeOfBoolean()];

            var item = new BerDataItem(buffer)
                .WriteBoolean(true);

            AssertThat.AreEqual(
                new byte[] { 0x01, 0x01, 0xFF },
                buffer);
            AssertThat.AreEqual(3, item.Offset);
        }

        [Test]
        public void WriteBooleanFalse()
        {
            var buffer = new byte[BerDataItem.SizeOfBoolean()];

            var item = new BerDataItem(buffer)
                .WriteBoolean(false);

            AssertThat.AreEqual(
                new byte[] { 0x01, 0x01, 0x00 },
                buffer);
            AssertThat.AreEqual(buffer.Length, item.Offset);
        }

        //---------------------------------------------------------------------
        // ReadInteger.
        //---------------------------------------------------------------------

        [Test]
        public void ReadUnsignedIntegerInSingleByte(
            [Values(0x48, 0x7F)] byte value)
        {
            var data = new byte[] { 0x02, 0x01, value };

            var item = new BerDataItem(data);

            AssertThat.AreEqual(DerTag.Integer, item.Tag);
            var nextItem = item.ReadInteger(out var decoded, out var positive);

            AssertThat.AreEqual(1, decoded.Length);
            AssertThat.AreEqual(value, decoded[0]);
            AssertThat.IsTrue(positive);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void ReadSignedIntegerInSingleByte()
        {
            var data = new byte[] { 0x02, 0x01, 0x80 };

            var item = new BerDataItem(data);

            AssertThat.AreEqual(DerTag.Integer, item.Tag);
            var nextItem = item.ReadInteger(out var decoded, out var positive);

            AssertThat.AreEqual(1, decoded.Length);
            AssertThat.AreEqual(0x80, decoded[0]);
            AssertThat.IsFalse(positive);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void ReadUnsignedIntegerInSingleByteWithPadding()
        {
            var data = new byte[] { 0x02, 0x02, 0x00, 0x80 };

            var item = new BerDataItem(data);

            AssertThat.AreEqual(DerTag.Integer, item.Tag);
            var nextItem = item.ReadInteger(out var decoded, out var positive);

            AssertThat.AreEqual(1, decoded.Length);
            AssertThat.AreEqual(128, decoded[0]);
            AssertThat.IsTrue(positive);
            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void WriteSignedInteger()
        {
            var integer = new byte[] { 0x80 };
            var bufferSize = BerDataItem.SizeOfInteger(integer, false);
            var buffer = new byte[bufferSize];

            var item = new BerDataItem(buffer)
                .WriteInteger(integer, false);

            AssertThat.AreEqual(
                new byte[] { 0x02, 0x01, 0x80 },
                buffer);
            AssertThat.AreEqual(buffer.Length, item.Offset);
        }

        [Test]
        public void WriteUnsignedInteger()
        {
            var integer = new byte[] { 0x7f };
            var bufferSize = BerDataItem.SizeOfInteger(integer, true);
            var buffer = new byte[bufferSize];

            var item = new BerDataItem(buffer)
                .WriteInteger(integer, true);

            AssertThat.AreEqual(
                new byte[] { 0x02, 0x01, 0x7f },
                buffer);
            AssertThat.AreEqual(buffer.Length, item.Offset);
        }

        [Test]
        public void WriteUnsignedIntegerWithLeadingZeros()
        {
            var integer = new byte[] { 0x00, 0x00, 0x7f };
            var bufferSize = BerDataItem.SizeOfInteger(integer, true);
            var buffer = new byte[bufferSize];

            var item = new BerDataItem(buffer)
                .WriteInteger(integer, true);

            AssertThat.AreEqual(
                new byte[] { 0x02, 0x01, 0x7f },
                buffer);
            AssertThat.AreEqual(buffer.Length, item.Offset);
        }

        [Test]
        public void WriteUnsignedIntegerWithPadding()
        {
            var integer = new byte[] { 0x80 };
            var bufferSize = BerDataItem.SizeOfInteger(integer, true);
            var buffer = new byte[bufferSize];

            var item = new BerDataItem(buffer)
                .WriteInteger(integer, true);

            AssertThat.AreEqual(
                new byte[] { 0x02, 0x02, 0x00, 0x80 },
                buffer);
            AssertThat.AreEqual(buffer.Length, item.Offset);
        }

        //---------------------------------------------------------------------
        // ReadSequence.
        //---------------------------------------------------------------------

        [Test]
        public void ReadSequenceOfNulls()
        {
            var data = new byte[] { 0x30, 0x04, 0x05, 0x00, 0x05, 0x00 };

            var item = new BerDataItem(data);

            AssertThat.AreEqual(DerTag.Sequence, item.Tag);
            var nextItem = item.ReadSequenceStart(out var length);

            AssertThat.AreEqual(4, length);

            nextItem = nextItem.ReadNull();
            nextItem = nextItem.ReadNull();

            AssertThat.IsFalse(nextItem.CanRead);
        }

        [Test]
        public void WriteSequenceOfNulls()
        {
            var bufferSize = BerDataItem.SizeOfSequence(2 * BerDataItem.SizeOfNull());
            var buffer = new byte[bufferSize];

            var item = new BerDataItem(buffer)
                .WriteSequenceStart(4)
                .WriteNull()
                .WriteNull();

            AssertThat.AreEqual(
                new byte[] { 0x30, 0x04, 0x05, 0x00, 0x05, 0x00 },
                buffer);
            AssertThat.AreEqual(buffer.Length, item.Offset);
        }

        [Test]
        public void WriteSequenceOf128Nulls()
        {
            var bufferSize = BerDataItem.SizeOfSequence(128 * BerDataItem.SizeOfNull());
            var buffer = new byte[bufferSize];

            var item = new BerDataItem(buffer)
                .WriteSequenceStart(128);

            AssertThat.AreEqual(
                new byte[] { 0x30, 0x82, 0x00, 0x80 },
                buffer.Take(4).ToArray());
            AssertThat.AreEqual(4, item.Offset);
        }

        [Test]
        public void WriteSequenceOf65536Nulls()
        {
            var bufferSize = BerDataItem.SizeOfSequence(65536 * BerDataItem.SizeOfNull());
            var buffer = new byte[bufferSize];

            var item = new BerDataItem(buffer)
                .WriteSequenceStart(65536);

            AssertThat.AreEqual(
                new byte[] { 0x30, 0x84, 0x00, 0x01, 0x00, 0x00 },
                buffer.Take(6).ToArray());
            AssertThat.AreEqual(6, item.Offset);
        }
    }
}
