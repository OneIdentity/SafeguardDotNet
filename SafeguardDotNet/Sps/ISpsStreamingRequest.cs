using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace OneIdentity.SafeguardDotNet.Sps
{
    public interface ISpsStreamingRequest : IDisposable
    {
        /// <summary>
        /// Call a Safeguard Sps POST API providing a stream as request content. If there is a failure a SafeguardDotNetException will be thrown.
        /// </summary>
        /// <param name="relativeUrl">Relative URL of the service to use.</param>
        /// <param name="stream">Stream to upload as request content.</param>
        /// <param name="progress">Optionally report upload progress.</param>
        /// <param name="parameters">Additional parameters to add to the URL.</param>
        /// <param name="additionalHeaders">Additional headers to add to the request.</param>
        /// <param name="cancellationToken">Optional cancellation token.</param>
        /// <returns>Response body as a string.</returns>
        Task<string> UploadAsync(string relativeUrl, Stream stream, IProgress<TransferProgress> progress = null, IDictionary<string, string> parameters = null, IDictionary<string, string> additionalHeaders = null, CancellationToken? cancellationToken = null);
    }
}
