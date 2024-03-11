using Jpki.Powershell.Runtime;
using Jpki.Powershell.Runtime.Http;
using Jpki.Security.WebAuthn;
using System.Diagnostics;
using System.Linq;
using System.Management.Automation;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Jpki.Powershell.Security.WebAuthn
{
    [Cmdlet(VerbsCommon.New, "BrowserWebAuthnCredential")]
    public class NewBrowserWebAuthnCredential : AsyncCmdletBase<Credential>
    {
        protected override async Task<Credential> ProcessRecordAsync(
            CancellationToken cancellationToken)
        {
            using (var server = new RegisterCredentialServer())
            {
                var completedTask = server.RunAsync(cancellationToken);
                Browser.Navigate(server.BaseUri);

                //
                // Wait for user to complete interaction.
                //
                await completedTask.ConfigureAwait(true);
            }
            throw new PSNotImplementedException();
        }

        private class RegisterCredentialServer : HttpServer
        {
            protected override void HandleRequest(
                HttpListenerRequest request,
                HttpListenerResponse response)
            {
                if (request.HttpMethod == "GET" && request.RawUrl == "/")
                {
                    //
                    // Serve HTML page.
                    //
                    using (var outputStream = response.OutputStream)
                    using (var inputStream = GetType()
                        .Assembly
                        .GetManifestResourceStream(typeof(NewBrowserWebAuthnCredential) + ".html"))
                    {
                        Debug.Assert(inputStream != null);
                        if (inputStream != null)
                        {
                            response.ContentType = "text/html";
                            response.StatusCode = (int)HttpStatusCode.OK;
                            inputStream.CopyTo(response.OutputStream);
                        }
                        else
                        {
                            response.StatusCode = (int)HttpStatusCode.NotFound;
                        }
                    }
                }
                else if (request.HttpMethod == "GET" && request.RawUrl == "/options")
                {
                    //
                    // Serve publicKeyCredentialCreationOptions.
                    //
                    var options = new {
                        challenge = "..."
                    };

                }
                else if (request.HttpMethod == "POST")
                {
                    //
                    // Accept post-back.
                    //

                    Stop();
                }
                else
                {
                    response.StatusCode = (int)HttpStatusCode.MethodNotAllowed;
                }
            }
        }
    }
}
