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
using System.Runtime.InteropServices;

namespace Jpki.Interop
{
    internal static class Unmanaged
    {
        /// <summary>
        /// Marshal a managed byte array to a block of unmanaged memory.
        /// </summary>
        public static IDisposable ByteArrayToPtr(
            byte[]? array,
            out IntPtr ptr)
        {
            if (array == null)
            {
                ptr = IntPtr.Zero;
                return NullDisposable.Instance;
            }
            else
            {
                var memory = LocalAllocSafeHandle.LocalAlloc((uint)array.Length);
                ptr = memory.DangerousGetHandle();

                Marshal.Copy(array, 0, ptr, array.Length);
                return memory;
            }
        }

        /// <summary>
        /// Marshal an unmanaged byte array to a managed array.
        /// </summary>
        public static byte[]? PtrToByteArray(IntPtr ptr, uint length)
        {
            if (ptr == IntPtr.Zero)
            {
                return null;
            }

            var array = new byte[(int)length];
            Marshal.Copy(ptr, array, 0, (int)length);
            return array;
        }

        /// <summary>
        /// Marshal an unmanaged byte array to a managed array.
        /// </summary>
        public static byte[] NonNullPtrToByteArray(IntPtr ptr, uint length)
        {
            Debug.Assert(ptr != IntPtr.Zero);

            var array = new byte[(int)length];
            Marshal.Copy(ptr, array, 0, (int)length);
            return array;
        }

        /// <summary>
        /// Marshal a managed struct array to a block of unmanaged memory.
        /// </summary>
        public static IDisposable StructArrayToPtr<T>(
            T[]? array,
            out IntPtr ptr)
            where T : struct
        {
            if (array == null)
            {
                ptr = IntPtr.Zero;
                return NullDisposable.Instance;
            }
            else
            {
                var memory = LocalAllocSafeHandle.LocalAlloc(
                    (uint)(array.Length * Marshal.SizeOf<T>()));
                ptr = memory.DangerousGetHandle();

                for (var i = 0; i < array.Length; i++)
                {
                    Marshal.StructureToPtr(
                        array[i],
                        IntPtr.Add(ptr, i * Marshal.SizeOf<T>()),
                        false);
                }

                return memory;
            }
        }

        /// <summary>
        /// Create a double-pointer for a single-pointer.
        /// </summary>
        public static IDisposable PtrToDoublePtr(IntPtr ptr, out IntPtr pptr)
        {
            var memory = LocalAllocSafeHandle.LocalAlloc(
                (uint)Marshal.SizeOf<IntPtr>());

            pptr = memory.DangerousGetHandle();
            Marshal.WriteIntPtr(pptr, ptr);

            return memory;
        }

        public static IntPtr DoublePtrToPtr(IntPtr ptr)
        {
            return Marshal.ReadIntPtr(ptr);
        }

        public static IDisposable StructToPtr<T>(
            T? stucture,
            out IntPtr ptr)
            where T : struct
        {
            if (stucture == null)
            {
                ptr = IntPtr.Zero;
                return Disposable.Empty;
            }
            else
            {
                var memory = LocalAllocSafeHandle.LocalAlloc((uint)Marshal.SizeOf<T>());
                ptr = memory.DangerousGetHandle();

                Marshal.StructureToPtr(stucture, ptr, false);

                return memory;
            }
        }

        public static T[]? PtrToStructArray<T>(
            IntPtr ptr,
            uint count)
            where T : struct
        {
            if (ptr == IntPtr.Zero)
            {
                return null;
            }
            else if (count == 0)
            {
                return Array.Empty<T>();
            }

            var array = new T[count];

            for (var i = 0; i < count; i++)
            {
                array[i] = Marshal.PtrToStructure<T>(
                    IntPtr.Add(ptr, i * Marshal.SizeOf<T>()));
            }

            return array;
        }

        private sealed class NullDisposable : IDisposable
        {
            public static readonly IDisposable Instance = new NullDisposable();

            private NullDisposable()
            {
            }

            public void Dispose()
            {
            }
        }
    }
}
