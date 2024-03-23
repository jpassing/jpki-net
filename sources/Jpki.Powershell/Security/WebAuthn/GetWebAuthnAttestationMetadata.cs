using Jpki.Powershell.Runtime;
using Jpki.Powershell.Runtime.Http;
using Jpki.Powershell.Runtime.Text;
using Jpki.Security.WebAuthn.Metadata;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Jpki.Powershell.Security.WebAuthn
{
    [Cmdlet(VerbsCommon.Get, "WebAuthnAttestationMetadata")]
    public class GetWebAuthnAttestationMetadata
        : AsyncCmdletBase<IEnumerable<MetadataBlobPayload.Entry>> // TODO: test
    {
        private const string FidoParameterSet = null;
        private const string U2fParameterSet = null;

        //---------------------------------------------------------------------
        // Fido parameter set.
        //---------------------------------------------------------------------

        [Parameter(Mandatory = false, ParameterSetName = nameof(FidoParameterSet))]
        public string? Aaguid { get; set; }

        //---------------------------------------------------------------------
        // Detailed parameter set.
        //---------------------------------------------------------------------

        [Parameter(Mandatory = false, ParameterSetName = nameof(U2fParameterSet))]
        public string? Aaid { get; set; }

        protected override async Task<IEnumerable<MetadataBlobPayload.Entry>> ProcessRecordAsync(
            CancellationToken cancellationToken)
        {
            var payload = await MdsMetadataResource
                .DownloadAsync(cancellationToken)
                .ConfigureAwait(false);

            return payload
                .Entries
                .EnsureNotNull()
                .Where(e => this.Aaguid == null || this.Aaguid == e.AaguidString)
                .Where(e => this.Aaid == null || this.Aaguid == e.Aaid);
        }

        private class MdsMetadataResource : TextResource
        {
            /// <summary>
            /// Metadata URL as published on https://fidoalliance.org/metadata/.
            /// </summary>
            public static readonly Uri Url = new Uri("https://mds3.fidoalliance.org/");

            public override string ExpectedContentType => "application/octet-stream";

            public static async Task<MetadataBlobPayload> DownloadAsync(CancellationToken cancellationToken)
            {
                using (var restClient = new RestClient())
                {
                    var metadataJwt = await restClient
                        .Resource<MdsMetadataResource>(Url)
                        .Get()
                        .ExecuteAsync(cancellationToken)
                        .ConfigureAwait(false);

                    // TODO: Verify signature.
                    if (metadataJwt.Body != null &&
                        metadataJwt.Body.Split('.').Skip(1).FirstOrDefault() is string encodedPayload)
                    {
                        var payloadJson = Encoding.UTF8.GetString(Base64UrlEncoding.Decode(encodedPayload));
                        var payload =  Json.Deserialize<MetadataBlobPayload>(payloadJson);

                        return payload ?? throw new InvalidOperationException("Received invalid MDS metadata"); // TODO: improve
                    }

                    throw new InvalidOperationException("Received invalid MDS metadata");
                }
            }
        }
    }
}
