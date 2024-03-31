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

namespace Jpki.Format
{
    internal static class BigEndian
    {
        public static uint ReadByteArray(
            byte[] data,
            uint offset,
            uint length,
            out byte[] value)
        {
            value = new byte[length];
            Array.Copy(data, offset, value, 0, length);
            return length;
        }

        public static uint ReadUInt32(
            byte[] data,
            uint offset,
            out uint value)
        {
            value = (uint)(
                (data[offset + 0] << 24) |
                (data[offset + 1] << 16) |
                (data[offset + 2] << 8) |
                (data[offset + 3] << 0));
            return 4;
        }

        public static uint ReadUInt16(
            byte[] data,
            uint offset,
            out ushort value)
        {
            value = (ushort)(
                (data[offset + 0] << 8) |
                (data[offset + 1] << 0));
            return 2;
        }

        internal static uint ReadGuid(
            byte[] data,
            uint offset,
            out Guid guid)
        {
            //
            // NB. Guid assumes little endian, so we can't use the
            // existing constructor that takes a byte array.
            //
            ReadUInt32(data, offset + 0, out var a);
            ReadUInt16(data, offset + 4, out var b);
            ReadUInt16(data, offset + 6, out var c);

            guid = new Guid(
                a, b, c,
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
                data[offset + 12],
                data[offset + 13],
                data[offset + 14],
                data[offset + 15]);
            return 16;
        }
    }
}
