# JPKI.Net

## Jpki.Extensions

This library contains extension methods that "backport"
PKI-related methods introduced in .NET 5, 6, or 7 to older runtime versions, including:
	
* [`ECDsa.SignData`](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.ecdsa.verifydata?view=net-7.0)
	overloads that accept a `DSASignatureFormat` parameter.
* [`ECDsa.VerifyData`](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.ecdsa.signdata?view=net-7.0)
	overloads that accept a `DSASignatureFormat` parameter.
* [`{ECDSA, RSA}.ExportSubjectPublicKeyInfo`](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.asymmetricalgorithm.exportsubjectpublickeyinfo?view=net-7.0)
* [`{ECDSA, RSA}.ExportSubjectPublicKeyInfoPem `](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.asymmetricalgorithm.exportsubjectpublickeyinfopem?view=net-7.0)
* [`{ECDSA, RSA}.ImportSubjectPublicKeyInfo`](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.asymmetricalgorithm.importsubjectpublickeyinfo?view=net-7.0)
* [`{ECDSA, RSA}.ImportFromPem`](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.asymmetricalgorithm.importfrompem?view=net-7.0)
* [`RSA.ExportRSAPublicKey`](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsa.exportrsapublickey?view=net-7.0)
* [`RSA.ExportRSAPublicKeyPem`](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsa.exportrsapublickeypem?view=net-7.0)
* [`RSA.ImportRSAPublicKey`](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsa.importrsapublickey?view=net-7.0)
* [`X509Certificate2.ExportCertificatePem`](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificate2.exportcertificatepem?view=net-7.0)

The library 
[uses the Windows CryptoAPI and CNG native APIs to implement these "missing" methods](https://jpassing.com/2021/12/05/importing-rsa-public-keys-in-downlevel-dotnet-and-dotnet-framework-versions/).

`Jpki.Extensions` has no runtime dependencies and supports the following runtimes:
* .NET Framework 4.7+
* .NET 6.0+ (Windows)

## Jpki.Fido

This library is a managed wrapper for the (semi-documented) Windows Hello 
[WebAuthn API](https://github.com/microsoft/webauthn) to create WebAuthn
assertions and credentials in .NET.

`Jpki.Fido` depends on `Jpki.Extensions` but has no further runtime dependencies.
It supports the following runtimes:
* .NET Framework 4.7+
* .NET 6.0+ (Windows)

_All files in this repository are under the
[Apache License, Version 2.0](LICENSE.txt) unless noted otherwise._


