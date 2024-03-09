using Jpki.Powershell.Runtime;
using Jpki.Security.Cryptography;
using System.Management.Automation;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Jpki.Powershell.Security.Cryptography
{
    public static class X509Certificate2Cmdlets
    {
        public class ConvertFromPem : AsyncCmdletBase<X509Certificate2>
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

        public class ConvertToPem : AsyncCmdletBase<string>
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
