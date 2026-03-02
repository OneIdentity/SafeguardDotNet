// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet
{
    using System;
    using System.IO;
    using System.Net.Http;
    using System.Threading.Tasks;

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
        /// Asynchronously retrieves the response stream object. The stream is created on first call
        /// and cached for subsequent calls.
        /// </summary>
        /// <returns>A task representing the asynchronous operation. The task result contains the HTTP response body content as a stream.</returns>
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
