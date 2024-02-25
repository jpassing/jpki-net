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
    public class TestCborData
    {
        //---------------------------------------------------------------------
        // ToString.
        //---------------------------------------------------------------------

        [Test]
        public void Empty()
        {
            var data = System.Array.Empty<byte>();
            var text = new CborData(data).ToString();

            AssertThat.AreEqual("", text);
        }

        [Test]
        public void UnsignedIntegerSequence()
        {
            var data = new byte[] { 0x18, 11, 0x18, 22 };
            var text = new CborData(data).ToString();

            AssertThat.AreEqual("[uint] 11\r\n[uint] 22\r\n", text);
        }

        [Test]
        public void UnsignedInteger()
        {
            var data = new byte[] { 0x18, 100 };
            var text = new CborData(data).ToString();

            AssertThat.AreEqual("[uint] 100\r\n", text);
        }

        [Test]
        public void NegativeInteger()
        {
            var data = new byte[] { 0x20 };
            var text = new CborData(data).ToString();

            AssertThat.AreEqual("[nint] -1\r\n", text);
        }

        [Test]
        public void SimpleValueFalse()
        {
            var data = new byte[] { 0xf4 };
            var text = new CborData(data).ToString();

            AssertThat.AreEqual("[sval] False\r\n", text);
        }

        [Test]
        public void SimpleValue16()
        {
            var data = new byte[] { 0xf0 };
            var text = new CborData(data).ToString();

            AssertThat.AreEqual("[sval] 16\r\n", text);
        }

        [Test]
        public void SimpleValueBreak()
        {
            var data = new byte[] { 0xff };
            var text = new CborData(data).ToString();

            AssertThat.AreEqual("[sval] break\r\n", text);
        }

        [Test]
        public void ByteStringWithZeroLength()
        {
            var data = new byte[] { 0x40 };
            var text = new CborData(data).ToString();

            AssertThat.AreEqual("[bstr] \r\n", text);
        }

        [Test]
        public void ByteStringWithFourBytes()
        {
            var data = new byte[] { 0x44, 0x01, 0x02, 0x03, 0x04 };
            var text = new CborData(data).ToString();

            AssertThat.AreEqual("[bstr] 01-02-03-04\r\n", text);
        }

        [Test]
        public void TextStringWithZeroLength()
        {
            var data = new byte[] { 0x60 };
            var text = new CborData(data).ToString();

            AssertThat.AreEqual("[tstr] \r\n", text);
        }

        [Test]
        public void TextStringWithFourChars()
        {
            var data = new byte[] { 0x64, 0x49, 0x45, 0x54, 0x46 };
            var text = new CborData(data).ToString();

            AssertThat.AreEqual("[tstr] IETF\r\n", text);
        }

        [Test]
        public void ArrayWithZeroLength()
        {
            var data = new byte[] { 0x80 };
            var text = new CborData(data).ToString();

            AssertThat.AreEqual("[array(0)]\r\n", text);
        }

        [Test]
        public void ArrayWithThreeUnsignedIntegers()
        {
            var data = new byte[] { 0x83, 0x01, 0x02, 0x03 };
            var text = new CborData(data).ToString();

            AssertThat.AreEqual("[array(3)]\r", text.Split('\n')[0]);
            AssertThat.AreEqual("  [uint] 1\r", text.Split('\n')[1]);
            AssertThat.AreEqual("  [uint] 2\r", text.Split('\n')[2]);
            AssertThat.AreEqual("  [uint] 3\r", text.Split('\n')[3]);
        }

        [Test]
        public void ArrayWithIndefiniteLength()
        {
            var data = new byte[] { 0x9f, 0x01, 0x02, 0xff };
            var text = new CborData(data).ToString();

            AssertThat.AreEqual("[array()]\r", text.Split('\n')[0]);
            AssertThat.AreEqual("  [uint] 1\r", text.Split('\n')[1]);
            AssertThat.AreEqual("  [uint] 2\r", text.Split('\n')[2]);
        }

        [Test]
        public void MapWithZeroLength()
        {
            var data = new byte[] { 0xa0 };
            var text = new CborData(data).ToString();

            AssertThat.AreEqual("[map(0)]\r\n", text);
        }

        [Test]
        public void MapWithTwoUnsignedIntegerPairs()
        {
            var data = new byte[] { 0xa2, 0x01, 0x02, 0x03, 0x04 };
            var text = new CborData(data).ToString();

            AssertThat.AreEqual("[map(2)]\r", text.Split('\n')[0]);
            AssertThat.AreEqual("  [uint] 1: [uint] 2\r", text.Split('\n')[1]);
            AssertThat.AreEqual("  [uint] 3: [uint] 4\r", text.Split('\n')[2]);
        }

        [Test]
        public void MapWithIndefiniteLength()
        {
            var data = new byte[] { 0xbf, 0x01, 0x02, 0xff };
            var text = new CborData(data).ToString();

            AssertThat.AreEqual("[map()]\r", text.Split('\n')[0]);
            AssertThat.AreEqual("  [uint] 1: [uint] 2\r", text.Split('\n')[1]);
        }

        [Test]
        public void TaggedItemWithUnsignedInteger()
        {
            var data = new byte[] { 0xc1, 0x1a, 0x51, 0x4b, 0x67, 0xb0 };
            var text = new CborData(data).ToString();

            AssertThat.AreEqual("[tag] EpochBasedDateTime\r", text.Split('\n')[0]);
            AssertThat.AreEqual("  [uint] 1363896240\r", text.Split('\n')[1]);
        }
    }
}
