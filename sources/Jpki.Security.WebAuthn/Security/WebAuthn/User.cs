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

namespace Jpki.Security.WebAuthn
{
    /// <summary>
    /// Information about an User Entity
    /// </summary>
    public class User
    {
        /// <summary>
        /// Identifier for the User. 
        /// </summary>
        public byte[] Id { get; }

        /// <summary>
        /// Contains a detailed name for this account, such as 
        /// "john.p.smith@example.com".
        /// </summary>
        public string? Name { get; }

        /// <summary>
        /// Optional URL that can be used to retrieve an image containing the 
        /// user's current avatar, or a data URI that contains the image data.
        /// </summary>
        public Uri? Icon { get; }

        /// <summary>
        /// For User: Contains the friendly name associated with the user account 
        /// by the Relying Party, such as "John P. Smith".
        /// </summary>
        public string? DisplayName { get; }

        public User(byte[] identifier, string? name, string? displayName, Uri? icon)
        {
            this.Id = identifier.ExpectNotNull(nameof(identifier));
            this.Name = name;
            this.Icon = icon;
            this.DisplayName = displayName;
        }

        public User(string identifier, string? name, string? displayName, Uri? icon)
            : this(Encoding.UTF8.GetBytes(identifier), name, displayName, icon)
        {
        }
    }
}
