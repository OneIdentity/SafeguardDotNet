using System;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;

namespace OneIdentity.SafeguardDotNet
{
    /// <summary>
    /// Represents a streamed response
    /// </summary>
    public class StreamResponse : IDisposable
    {
        private bool _disposedValue;

        internal StreamResponse(HttpResponseMessage response, Action cleanup)
        {
            Response = response;
            Cleanup = cleanup;
        }

        private HttpResponseMessage Response { get; }

        private Action Cleanup { get; }

        private Stream Stream { get; set; }

        /// <summary>
        /// Get the response stream object
        /// </summary>
        /// <returns>The HTTP response body content as a stream</returns>
        public async Task<Stream> GetStream()
        {
            if (Stream == null)
            {
                Stream = await Response.Content.ReadAsStreamAsync();
            }
            return Stream;
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposedValue)
            {
                if (disposing)
                {
                    Response.Dispose();
                    Stream?.Dispose();
                    Cleanup();
                }

                _disposedValue = true;
            }
        }
        
        /// <summary>
        /// Disposes the stream and associated resources
        /// </summary>
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
