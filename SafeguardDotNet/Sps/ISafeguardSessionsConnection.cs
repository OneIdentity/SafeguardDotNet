// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.Sps
{
    using System;

    /// <summary>
    /// This is the reusable connection interface that can be used to call SPS API.
    /// </summary>
    public interface ISafeguardSessionsConnection : IDisposable
    {
        /// <summary>
        /// Call a Safeguard for Privileged Sessions API method and get any response as a string.
        /// If there is a failure a SafeguardDotNetException will be thrown.
        /// </summary>
        /// <param name="method">Safeguard method type to use.</param>
        /// <param name="relativeUrl">Relative URL of the service to use.</param>
        /// <param name="body">Request body to pass to the method.</param>
        /// <returns>Response body as a string.</returns>
        string InvokeMethod(Method method, string relativeUrl, string body = null);

        /// <summary>
        /// Call a Safeguard for Privileged Sessions API method and get a detailed response
        /// with status code, headers, and body. If there is a failure a SafeguardDotNetException
        /// will be thrown.
        /// </summary>
        /// <param name="method">HTTP method type to use.</param>
        /// <param name="relativeUrl">The url.</param>
        /// <param name="body">Request body to pass to the method.</param>
        /// <returns>Response with status code, headers, and body as string.</returns>
        FullResponse InvokeMethodFull(Method method, string relativeUrl, string body = null);

        /// <summary>
        /// Provides support for HTTP streaming requests
        /// </summary>
        ISpsStreamingRequest Streaming { get; }
    }
}
