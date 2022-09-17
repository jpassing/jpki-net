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

namespace Jpki.Security.WebAuthn
{
    /// <summary>
    /// Information about an RP Entity.
    /// </summary>
    public class RelyingParty
    {
        /// <summary>
        /// Identifier for the RP.
        /// </summary>
        public string Id { get; }

        /// <summary>
        /// Contains the friendly name of the Relying Party, such as "Acme Corporation", 
        /// "Widgets Inc" or "Awesome Site".
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// Optional URL pointing to RP's logo. 
        /// </summary>
        public Uri? Icon { get; }

        public RelyingParty(string id, string name, Uri? icon)
        {
            this.Id = id.ExpectNotNullOrEmpty(nameof(id));
            this.Name = name.ExpectNotNullOrEmpty(nameof(name));
            this.Icon = icon;
        }
    }
}
