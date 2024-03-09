using Jpki.Powershell.Runtime;
using Jpki.Security.Cryptography;
using System.Management.Automation;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Jpki.Powershell.Security.Cryptography
{
    public static class PemCmdlets
    {
        [Cmdlet(VerbsData.ConvertFrom, "Pem")]
        public class ConvertCertificateFromPem : AsyncCmdletBase<X509Certificate2>
        {
            [Parameter(Mandatory = true, ValueFromPipeline = true)]
            public string? Pem { get; set; }

            protected override Task<X509Certificate2> ProcessRecordAsync(
                CancellationToken cancellationToken)
            {
                var certificate =  X509Certificate2Extensions
                    .CreateFromPem(this.Pem.ExpectNotNull(nameof(this.Pem)));

                return Task.FromResult(certificate);
            }
        }

        [Cmdlet(VerbsData.ConvertTo, "Pem")]
        public class ConvertCertificateToPem : AsyncCmdletBase<string>
        {
            [Parameter(Mandatory = true, ValueFromPipeline = true)]
            public X509Certificate2? Certificate { get; set; }

            protected override Task<string> ProcessRecordAsync(
                CancellationToken cancellationToken)
            {
                var pem = this.Certificate
                    .ExpectNotNull(nameof(this.Certificate))
                    .ExportCertificatePem();

                return Task.FromResult(pem);
            }
        }
    }
}
