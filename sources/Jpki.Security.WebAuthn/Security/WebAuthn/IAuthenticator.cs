using Jpki.Security.Cryptography.Cose;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Jpki.Security.WebAuthn
{
    public interface IAuthenticator
    {
        /// <summary>
        /// Create a new credential.
        /// </summary>
        Task<Credential> CreateCredentialAsync(
            IntPtr windowHandle,
            RelyingParty relyingParty,
            User user,
            ClientData clientData,
            AttestationOptions options,
            CancellationToken cancellationToken);

        Task<Assertion> CreateAssertionAsync(
            IntPtr windowHandle,
            RelyingParty relyingParty,
            ClientData clientData,
            AssertionOptions options,
            CancellationToken cancellationToken);
    }

    /// <summary>
    /// Options for creating credential attestations.
    /// </summary>
    public class AttestationOptions
    {
        public CoseSignatureAlgorithm[] SignatureAlgorithms { get; set; }
            = new[] { CoseSignatureAlgorithm.ES256 };

        public AuthenticatorAttachment Authenticator { get; set; }
            = AuthenticatorAttachment.CrossPlatform;

        public UserVerificationRequirement UserVerification { get; set; }
            = UserVerificationRequirement.Preferred;

        public AttestationConveyance Attestation { get; set; }
            = AttestationConveyance.None;

        public ResidentKeyRequirement ResidentKey { get; set; }

        public TimeSpan Timeout { get; set; } = TimeSpan.Zero;
    }

    /// <summary>
    /// Options for creating assertions.
    /// </summary>
    public class AssertionOptions
    {
        public ICollection<CredentialId>? AllowedCredentials { get; set; }

        public AuthenticatorAttachment AuthenticatorAttachment { get; set; }
            = AuthenticatorAttachment.Any;

        public UserVerificationRequirement UserVerification { get; set; }
            = UserVerificationRequirement.Any;

        public TimeSpan Timeout { get; set; } = TimeSpan.Zero;
    }
}
