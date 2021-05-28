using System;
using System.Collections.Generic;
using OneIdentity.SafeguardDotNet.Event;

namespace OneIdentity.SafeguardDotNet
{
    /// <summary>
    /// This is the reusable connection interface that can be used to call SPS API.
    /// </summary>
    public interface ISafeguardSessionsConnection
    {
        /// <summary>
        /// Call a SafeguardForPrivilegedSessions API method and get a detailed response with status code, headers,
        /// and body. If there is a failure a SafeguardDotNetException will be thrown.
        /// </summary>
        /// <param name="method">HTTP method type to use.</param>
        /// <param name="relativeUrl">The url.</param>
        /// <param name="body">Request body to pass to the method.</param>
        /// <returns>Response with status code, headers, and body as string.</returns>
        FullResponse InvokeMethodFull(Method method, string relativeUrl, string body = null);
    }
}
