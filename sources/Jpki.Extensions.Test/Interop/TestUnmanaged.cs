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

using Jpki.Interop;
using NUnit.Framework;
using System;
using System.Runtime.InteropServices;

namespace Jpki.Test.Interop
{
    [TestFixture]
    public class TestUnmanaged
    {
        //---------------------------------------------------------------------
        // ByteArrayToPtr.
        //---------------------------------------------------------------------

        [Test]
        public void WhenArrayNull_ThenByteArrayToPtrReturnsNull()
        {
            using (var disposable = Unmanaged.ByteArrayToPtr(null, out var ptr))
            {
                Assert.IsNotNull(disposable);
                Assert.AreEqual(IntPtr.Zero, ptr);
            }
        }

        [Test]
        public void WhenArrayEmpty_ThenByteArrayToPtrReturnsPtr()
        {
            using (var disposable = Unmanaged.ByteArrayToPtr(Array.Empty<byte>(), out var ptr))
            {
                Assert.IsNotNull(disposable);
                Assert.AreNotEqual(IntPtr.Zero, ptr);
            }
        }

        [Test]
        public void WhenArrayNotEmpty_ThenByteArrayToPtrReturnsPtr()
        {
            var array = new byte[] { 1, 2, 3 };
            using (var disposable = Unmanaged.ByteArrayToPtr(array, out var ptr))
            {
                Assert.IsNotNull(disposable);
                Assert.AreNotEqual(IntPtr.Zero, ptr);

                var arrayCopy = Unmanaged.PtrToByteArray(ptr, (uint)array.Length);
                CollectionAssert.AreEquivalent(array, arrayCopy);
            }
        }

        //---------------------------------------------------------------------
        // ByteArrayToPtr.
        //---------------------------------------------------------------------

        //---------------------------------------------------------------------
        // StructArrayToPtr.
        //---------------------------------------------------------------------

        private struct SampleStruct
        {
            public uint Member;
        }

        [Test]
        public void WhenArrayNull_ThenStructArrayToPtrReturnsNull()
        {
            using (var disposable = Unmanaged.StructArrayToPtr<SampleStruct>(null, out var ptr))
            {
                Assert.IsNotNull(disposable);
                Assert.AreEqual(IntPtr.Zero, ptr);
            }
        }

        [Test]
        public void WhenArrayEmpty_ThenStructArrayToPtrReturnsPtr()
        {
            using (var disposable = Unmanaged.StructArrayToPtr(Array.Empty<SampleStruct>(), out var ptr))
            {
                Assert.IsNotNull(disposable);
                Assert.AreNotEqual(IntPtr.Zero, ptr);
            }
        }

        [Test]
        public void WhenArrayNotEmpty_ThenStructArrayToPtrReturnsPtr()
        {
            using (var disposable = Unmanaged.StructArrayToPtr(new SampleStruct[1], out var ptr))
            {
                Assert.IsNotNull(disposable);
                Assert.AreNotEqual(IntPtr.Zero, ptr);
            }
        }

        //---------------------------------------------------------------------
        // StructToPtr.
        //---------------------------------------------------------------------

        [Test]
        public void StructToPtr()
        {
            using (Unmanaged.StructToPtr<SampleStruct>(new SampleStruct()
            {
                Member = 42
            }, out var structPtr))
            {
                Assert.AreEqual(42, Marshal.PtrToStructure<SampleStruct>(structPtr).Member);
            }
        }

        //---------------------------------------------------------------------
        // PtrToDoublePtr.
        //---------------------------------------------------------------------

        [Test]
        public void PtrToDoublePtr()
        {
            using (Unmanaged.PtrToDoublePtr(new IntPtr(42), out var pptr))
            {
                var ptr = Unmanaged.DoublePtrToPtr(pptr);

                Assert.AreEqual(42, ptr.ToInt32());
            }
        }
    }
}
