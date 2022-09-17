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
using Jpki.Security.Cryptography;
using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Jpki.Security.Cryptography.Cose
{
    /// <summary>
    /// Base class for COSE public keys.
    /// </summary>
    public abstract class CosePublicKey : IDisposable
    {
        /// <summary>
        /// Type of key.
        /// </summary>
        public CoseKeyType KeyType { get; }

        /// <summary>
        /// Algorithm the key is intended to be used for.
        /// </summary>
        public CoseSignatureAlgorithm Algorithm { get; }

        protected CosePublicKey(CoseKeyType keyType, CoseSignatureAlgorithm algorithm)
        {
            this.KeyType = keyType;
            this.Algorithm = algorithm;
        }

        //---------------------------------------------------------------------
        // Decoding.
        //---------------------------------------------------------------------

        private static void DecodeKeyType(
            CborData data,
            out CoseKeyType keyType,
            out CoseSignatureAlgorithm algorithm)
        {
            //
            // Keys are encoded as a CBOR map.
            // 
            // COSE Key Common Parameters,
            // see https://www.rfc-editor.org/rfc/rfc9052#section-7.1.
            //
            // Name     Label   CBOR Type       Description
            // -------- ------- --------------- -----------------------------
            // kty	    1	    tstr / int      Identification of the key type
            // kid	    2	    bstr            Key identification value
            // alg	    3	    tstr / int      Key usage restriction to this algorithm
            // key_ops	4	    [+ (tstr/int)]	Restrict set of permissible operations
            // Base IV	5	    bstr            Base IV to be xor-ed with Partial IVs
            //
            // Go over map and determine key type and algorithm. Ignore
            // other parameters (because their meaning isn't clear without
            // knowing the algorithm first).
            //

            keyType = 0;
            algorithm = 0;

            Debug.Assert(!Enum.IsDefined(typeof(CoseKeyType), keyType));
            Debug.Assert(!Enum.IsDefined(typeof(CoseSignatureAlgorithm), algorithm));

            var nextItem = data.Read().ReadMapStart(out var mapLength);

            for (var i = 0;
                i < mapLength || (mapLength == null && !nextItem.IsBreak);
                i++)
            {
                nextItem = nextItem.ReadSignedOrUnsignedInteger(out var label);

                switch (label)
                {
                    case 1:
                        //
                        // Key type, see
                        // https://www.iana.org/assignments/cose/cose.xhtml#key-type.
                        //
                        nextItem = nextItem.ReadSignedOrUnsignedInteger(out var kty);
                        keyType = (CoseKeyType)kty;
                        break;

                    case 3:
                        nextItem = nextItem.ReadSignedOrUnsignedInteger(out var alg);
                        algorithm = (CoseSignatureAlgorithm)alg;
                        break;

                    default:
                        nextItem = nextItem.Skip();
                        break;
                }
            }

            if (keyType == 0 || algorithm == 0)
            {
                throw new MalformedCoseKeyException(
                    "The key must contain a key type and algorithm");
            }
        }

        private static void DecodeEccParameters(
            CborData data,
            out CoseEllipticCurves ecCurve,
            out byte[] x,
            out byte[] y)
        {
            //
            // ECC parameters (kty == 2),
            // see https://www.rfc-editor.org/rfc/rfc9053.html#section-7.1.1
            //
            // Kty Name Label CBOR Type   Description
            // --- ---- ----- ----------- -------------
            // 2   crv  -1    int/tstr    EC identifier
            // 2   x    -2    bstr        x-coordinate
            // 2   y    -3    bstr/bool   y-coordinate
            // 2   d    -4    bstr        Private key
            //
            // For public keys, it is REQUIRED that "crv", "x", and "y" be
            // present in the structure. 
            //

            ecCurve = 0;
            byte[] xValue = null;
            byte[] yValue = null;

            Debug.Assert(!Enum.IsDefined(typeof(CoseEllipticCurves), ecCurve));

            var nextItem = data.Read().ReadMapStart(out var mapLength);

            for (var i = 0;
                i < mapLength || (mapLength == null && !nextItem.IsBreak);
                i++)
            {
                nextItem = nextItem.ReadSignedOrUnsignedInteger(out var label);

                switch (label)
                {
                    case -1: // EC identifier.
                        nextItem = nextItem.ReadSignedOrUnsignedInteger(out var crv);
                        ecCurve = (CoseEllipticCurves)crv;
                        break;

                    case -2: // x-coordinate.
                        nextItem = nextItem.ReadByteString(out xValue);
                        break;

                    case -3: // y-coordinate.
                        nextItem = nextItem.ReadByteString(out yValue);
                        break;

                    default:
                        nextItem = nextItem.Skip();
                        break;
                }
            }

            if (ecCurve == 0 || xValue == null || yValue == null)
            {
                throw new MalformedCoseKeyException(
                    "The EC2 key must contain a curve, x, and y parameters");
            }

            x = xValue;
            y = yValue;
        }

        private static void DecodeRsaParameters(
            CborData data,
            out byte[] modulus,
            out byte[] exponent)
        {
            //
            // RSA parameters (kty == 3),
            // see https://www.rfc-editor.org/rfc/rfc8230.html#section-4,
            //
            // Name  Label  CBOR  Description                       
            //              Type                                    
            // ----- ------ ----------------------------------------
            // n     -1     bstr  the RSA modulus n                 
            // e     -2     bstr  the RSA public exponent e         
            // d     -3     bstr  the RSA private exponent d        
            // p     -4     bstr  the prime factor p of n           
            // q     -5     bstr  the prime factor q of n           
            // dP    -6     bstr  dP is d mod (p - 1)               
            // dQ    -7     bstr  dQ is d mod (q - 1)               
            // qInv  -8     bstr  qInv is the CRT coefficient       
            //                    q^(-1) mod p                      
            // other -9     array other prime infos, an array       
            // r_i   -10    bstr  a prime factor r_i of n, where i  
            //                    >= 3                              
            // d_i   -11    bstr  d_i = d mod (r_i - 1)             
            // t_i   -12    bstr  the CRT coefficient t_i = (r_1 *  
            //                    r_2 * ... * r_(i-1))^(-1) mod r_i 
            //
            // For public keys, the fields 'n' and 'e' MUST be present.  All
            // other fields defined in the following table below MUST be absent.
            //

            byte[] modulusValue = null;
            byte[] exponentValue = null;

            var nextItem = data.Read().ReadMapStart(out var mapLength);

            for (var i = 0;
                i < mapLength || (mapLength == null && !nextItem.IsBreak);
                i++)
            {
                nextItem = nextItem.ReadSignedOrUnsignedInteger(out var label);

                switch (label)
                {
                    case -1: // RSA modulus n.
                        nextItem = nextItem.ReadByteString(out modulusValue);
                        break;

                    case -2: // RSA public exponent e.
                        nextItem = nextItem.ReadByteString(out exponentValue);
                        break;

                    default:
                        nextItem = nextItem.Skip();
                        break;
                }
            }

            if (modulusValue == null || exponentValue == null)
            {
                throw new MalformedCoseKeyException(
                    "The RSA key must contain a modulus and exponent");
            }

            modulus = modulusValue;
            exponent = exponentValue;
        }

        /// <summary>
        /// Decode key from CBOR.
        /// </summary>
        internal static CosePublicKey Decode(CborData data)
        {
            //
            // Parameters are encoded as a map, and the map isn't ordered,
            // so we need two passes.
            //
            DecodeKeyType(data, out var keyType, out var algorithm);

            switch (keyType)
            {
                case CoseKeyType.EC2:
                    {
                        DecodeEccParameters(data, out var curve, out var x, out var y);
                        return new CoseEcdsaPublicKey(algorithm, curve, x, y);
                    }

                case CoseKeyType.RSA:
                    {
                        DecodeRsaParameters(data, out var modulus, out var exponent);
                        return new CoseRsaPublicKey(algorithm, modulus, exponent);
                    }

                default:
                    throw new NotImplementedException(
                        $"The COSE key type {keyType} is not supported");
            }
        }

        /// <summary>
        /// Use the key to verify a signature.
        /// </summary>
        public abstract bool VerifySignature(
            byte[] data,
            byte[] signature);

        protected virtual void Dispose(bool disposing)
        {
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }

    public class CoseEcdsaPublicKey : CosePublicKey
    {
        public ECDsa Key { get; }

        private static ECCurve LookupNamedCurve(CoseEllipticCurves curve)
        {
            switch (curve)
            {
                case CoseEllipticCurves.P256:
                    return ECCurve.NamedCurves.nistP256;

                case CoseEllipticCurves.P384:
                    return ECCurve.NamedCurves.nistP384;

                case CoseEllipticCurves.P521:
                    return ECCurve.NamedCurves.nistP521;

                default:
                    throw new ArgumentException(
                        $"The curve {curve} is not supported");
            }
        }

        internal CoseEcdsaPublicKey(
            CoseSignatureAlgorithm algorithm,
            CoseEllipticCurves curve,
            byte[] x,
            byte[] y)
            : base(CoseKeyType.EC2, algorithm)
        {
            Debug.Assert(algorithm != CoseSignatureAlgorithm.ES256 || x.Length == 32);
            Debug.Assert(algorithm != CoseSignatureAlgorithm.ES256 || y.Length == 32);

            var parameters = new ECParameters()
            {
                Q = new ECPoint()
                {
                    X = x.ExpectNotNull(nameof(x)),
                    Y = y.ExpectNotNull(nameof(y))
                },
                Curve = LookupNamedCurve(curve)
            };
            parameters.Validate();

            this.Key = ECDsa.Create(parameters);
        }

        public override bool VerifySignature(
            byte[] data,
            byte[] signature)
        {
            //
            // NB. WebAuthN signatures are DER-formatted.
            //
            return this.Key.VerifyData(
                data,
                signature,
                this.Algorithm.GetHashAlgorithm().GetName(),
                DSASignatureFormat.Rfc3279DerSequence);
        }

        protected override void Dispose(bool disposing)
        {
            this.Key.Dispose();
            base.Dispose(disposing);
        }
    }

    public class CoseRsaPublicKey : CosePublicKey
    {
        public RSA Key { get; }

        internal CoseRsaPublicKey(
            CoseSignatureAlgorithm algorithm,
            byte[] modulus,
            byte[] exponent)
            : base(CoseKeyType.RSA, algorithm)
        {
            this.Key = RSA.Create();
            this.Key.ImportParameters(new RSAParameters()
            {
                Exponent = exponent,
                Modulus = modulus
            });
        }

        public override bool VerifySignature(
            byte[] data,
            byte[] signature)
        {
            return this.Key.VerifyData(
                data,
                signature,
                this.Algorithm.GetHashAlgorithm().GetName(),
                this.Algorithm.GetRSASignaturePadding());
        }

        protected override void Dispose(bool disposing)
        {
            this.Key.Dispose();
            base.Dispose(disposing);
        }
    }

    internal static class CborDataItemExtensions
    {
        public static CborDataItem ReadSignedOrUnsignedInteger(
            this CborDataItem item,
            out long value)
        {
            if (item.MajorType == CborMajorType.TextString)
            {
                item = item.ReadTextString(out var text);
                value = long.Parse(text);
            }
            else if (item.MajorType == CborMajorType.UnsignedInteger)
            {
                item = item.ReadUnsignedInteger(out var unsigned);

                if (unsigned > long.MaxValue)
                {
                    throw new OverflowException();
                }

                value = (long)unsigned;
            }
            else
            {
                item = item.ReadNegativeInteger(out value);
            }

            return item;
        }
    }
}
