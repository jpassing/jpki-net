using Jpki.Powershell.Runtime;
using Jpki.Security.Cryptography.Cose;
using Jpki.Security.WebAuthn;
using Jpki.Security.WebAuthn.Windows;
using System;
using System.Management.Automation;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Jpki.Powershell.Security.WebAuthn
{
    [Cmdlet(VerbsCommon.New, "WebAuthnCredential")]
    public class NewWebAuthnCredential : AsyncCmdletBase<Credential>
    {
        private const string SimpleParameterSet = null;
        private const string DetailedParameterSet = null;

        //---------------------------------------------------------------------
        // Detailed parameter set.
        //---------------------------------------------------------------------

        [Parameter(Mandatory = true, ParameterSetName = nameof(DetailedParameterSet))]
        public RelyingParty? RelyingParty { get; set; }

        [Parameter(Mandatory = true, ParameterSetName = nameof(DetailedParameterSet))]
        public User? User { get; set; }

        [Parameter(Mandatory = true, ParameterSetName = nameof(DetailedParameterSet))]
        public ClientData? ClientData { get; set; }

        //---------------------------------------------------------------------
        // Detailed parameter set
        //---------------------------------------------------------------------

        [Parameter(Mandatory = true, ParameterSetName = nameof(SimpleParameterSet))]
        public string? RelyingPartyId { get; set; }

        [Parameter(Mandatory = true, ParameterSetName = nameof(SimpleParameterSet))]
        public string? UserId { get; set; }

        [Parameter(Mandatory = true, ParameterSetName = nameof(SimpleParameterSet))]
        public string? ClientDataJson { get; set; }

        //---------------------------------------------------------------------
        // Common parameters.
        //---------------------------------------------------------------------

        [Parameter(Mandatory = false, ParameterSetName = nameof(SimpleParameterSet))]
        [Parameter(Mandatory = false, ParameterSetName = nameof(DetailedParameterSet))]
        public WindowsHello.AttestationOptions? AttestationOptions { get; set; }

        protected override Task<Credential> ProcessRecordAsync(
            CancellationToken cancellationToken)
        {
            if (this.RelyingParty != null &&
                this.User != null &&
                this.ClientData != null)
            {
                //
                //  Detailed parameter set.
                //
                return WindowsHello.CreateCredentialAsync(
                    IntPtr.Zero,
                    this.RelyingParty,
                    this.User,
                    this.ClientData,
                    this.AttestationOptions ?? new WindowsHello.AttestationOptions(),
                    cancellationToken);
            }
            else if (this.RelyingPartyId != null &&
                this.UserId != null &&
                this.ClientDataJson != null)
            {
                //
                //  Simple parameter set.
                //
                return WindowsHello.CreateCredentialAsync(
                    IntPtr.Zero,
                    new RelyingParty(this.RelyingPartyId, this.RelyingPartyId, null),
                    new User(Encoding.UTF8.GetBytes(this.UserId), this.UserId, null, null),
                    new ClientData(Encoding.UTF8.GetBytes(this.ClientDataJson), CoseHashAlgorithm.SHA_256),
                    this.AttestationOptions ?? new WindowsHello.AttestationOptions(),
                    cancellationToken);
            }
            else
            {
                throw new PSArgumentException("The arguments passed to the cmdlet are invalid");
            }
        }
    }
}
