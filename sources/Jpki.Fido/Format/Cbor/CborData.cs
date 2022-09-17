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
using System.Text;

namespace Jpki.Format.Cbor
{
    /// <summary>
    /// Blob of CBOR-encoded data.
    /// </summary>
    internal struct CborData
    {
        private readonly byte[] data;
        private readonly uint offset;
        private readonly uint length;

        public CborData(byte[] data, uint offset, uint length)
        {
            this.data = data.ExpectNotNull(nameof(data));
            this.offset = offset;
            this.length = length;
        }

        public CborData(byte[] data)
            : this(data, 0, (uint)data.Length)
        {
        }

        public CborDataItem Read()
        {
            return new CborDataItem(this.data, this.offset, this.length);
        }

        public override string ToString()
        {
            var serializer = new Serializer();

            var item = Read();
            while (item.CanRead)
            {
                item = serializer.Visit(item);
            }

            return serializer.ToString();
        }

        //---------------------------------------------------------------------
        // Inner class.
        //---------------------------------------------------------------------

        private class Serializer
        {
            private int indentLevel = 0;
            private readonly StringBuilder buffer = new StringBuilder();

            private void OutputLine(string text)
            {
                this.buffer.Append(new string(' ', this.indentLevel * 2));
                this.buffer.Append(text);
                this.buffer.AppendLine();
            }

            private void OutputMapKey(string text)
            {
                this.buffer.Append(new string(' ', this.indentLevel * 2));
                this.buffer.Append(text);
            }

            private void OutputMapValue(string text)
            {
                this.buffer.Append(": ");
                this.buffer.Append(text);
                this.buffer.AppendLine();
            }

            public CborDataItem Visit(CborDataItem dataItem)
            {
                return Visit(dataItem, OutputLine);
            }

            private CborDataItem Visit(
                CborDataItem dataItem,
                Action<string> output)
            {
                CborDataItem nextItem;
                switch (dataItem.MajorType)
                {
                    case CborMajorType.UnsignedInteger:
                        nextItem = dataItem.ReadUnsignedInteger(out var unsignedInt);
                        output("[uint] " + unsignedInt);
                        return nextItem;

                    case CborMajorType.NegativeInteger:
                        nextItem = dataItem.ReadNegativeInteger(out var negativeInt);
                        output("[nint] " + negativeInt);
                        return nextItem;

                    case CborMajorType.ByteString:
                        nextItem = dataItem.ReadByteString(out var byteString);
                        output("[bstr] " + BitConverter.ToString(byteString));
                        return nextItem;

                    case CborMajorType.TextString:
                        nextItem = dataItem.ReadTextString(out var textString);
                        output("[tstr] " + textString);
                        return nextItem;

                    case CborMajorType.Array:
                        nextItem = dataItem.ReadArrayStart(out var arrayLength);

                        output($"[array({arrayLength})]");

                        this.indentLevel++;

                        for (var i = 0;
                             i < arrayLength || (arrayLength == null && !nextItem.IsBreak);
                             i++)
                        {
                            nextItem = Visit(nextItem);
                        }

                        this.indentLevel--;
                        return nextItem;

                    case CborMajorType.Map:
                        nextItem = dataItem.ReadMapStart(out var mapLength);

                        output($"[map({mapLength})]");
                        this.indentLevel++;

                        for (var i = 0;
                            i < mapLength || (mapLength == null && !nextItem.IsBreak);
                            i++)
                        {
                            nextItem = Visit(nextItem, OutputMapKey);
                            nextItem = Visit(nextItem, OutputMapValue);
                        }

                        this.indentLevel--;
                        return nextItem;

                    case CborMajorType.TaggedItem:
                        nextItem = dataItem.ReadTaggedItemStart(out var tag);
                        output("[tag] " + tag);

                        this.indentLevel++;
                        nextItem = Visit(nextItem);
                        this.indentLevel--;

                        return nextItem;

                    case CborMajorType.FloatingPointOrSimpleValue:
                        if (dataItem.IsSimpleValue)
                        {
                            nextItem = dataItem.ReadSimpleValue(out var simpleValue);
                            output("[sval] " + simpleValue);
                            return nextItem;
                        }
                        else if (dataItem.IsBreak)
                        {
                            nextItem = dataItem.ReadSimpleValue(out var simpleValue);
                            output("[sval] break");
                            return nextItem;
                        }
                        else if (dataItem.IsFloatingPoint)
                        {
                            throw new NotImplementedException(
                                "Floating point data is not supported");
                        }
                        else
                        {
                            throw new NotImplementedException(
                                $"Unrecognized data item {dataItem}");
                        }

                    default:
                        throw new NotImplementedException(
                            $"Unrecognized data item {dataItem}");
                }
            }

            public override string ToString()
            {
                return this.buffer.ToString();
            }
        }
    }
}