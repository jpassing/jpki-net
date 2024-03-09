using System.Threading;
using System.Threading.Tasks;

#pragma warning disable VSTHRD002 // Avoid problematic synchronous waits

namespace Jpki.Powershell.Runtime
{
    public abstract class AsyncCmdletBase<TResult> : CmdletBase
    {
        //---------------------------------------------------------------------
        // Begin processing.
        //---------------------------------------------------------------------

        protected override sealed void BeginProcessing(CancellationToken cancellationToken)
        {
            BeginProcessingAsync(cancellationToken).Wait(cancellationToken);
        }

        protected virtual Task BeginProcessingAsync(CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        //---------------------------------------------------------------------
        // Process.
        //---------------------------------------------------------------------

        protected override sealed void ProcessRecord(CancellationToken cancellationToken)
        {
            var result = ProcessRecordAsync(cancellationToken)
                .GetResult<TResult>(cancellationToken);
            WriteObject(result, true);
        }

        protected abstract Task<TResult> ProcessRecordAsync(CancellationToken cancellationToken);


        //---------------------------------------------------------------------
        // End processing.
        //---------------------------------------------------------------------

        protected override sealed void EndProcessing(CancellationToken cancellationToken)
        {
            EndProcessingAsync(cancellationToken).Wait(cancellationToken);
        }

        protected virtual Task EndProcessingAsync(CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }
    }
}
