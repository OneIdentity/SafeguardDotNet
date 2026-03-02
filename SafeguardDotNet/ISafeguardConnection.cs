// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet
{
    using System;
    using System.Collections.Generic;
    using System.Security;

    using OneIdentity.SafeguardDotNet.Event;
    using OneIdentity.SafeguardDotNet.Sps;

    /// <summary>
    /// This is the reusable connection interface that can be used to call Safeguard API after
    /// connecting using the API access token obtained during authentication.
    /// </summary>
    public interface ISafeguardConnection : IDisposable
    {
        /// <summary>
        /// Number of minutes remaining in the lifetime of the Safeguard API access token.
        /// </summary>
        /// <returns></returns>
        int GetAccessTokenLifetimeRemaining();

        /// <summary>
        /// Request a new Safeguard API access token with the underlying credentials used to
        /// initially create the connection.
        /// </summary>
        void RefreshAccessToken();

        /// <summary>
        /// Call a Safeguard API method and get any response as a string. Some Safeguard API
        /// methods will return an empty body. If there is a failure a SafeguardDotNetException
        /// will be thrown.
        /// </summary>
        /// <param name="service">Safeguard service to call.</param>
        /// <param name="method">Safeguard method type to use.</param>
        /// <param name="relativeUrl">Relative URL of the service to use.</param>
        /// <param name="body">Request body to pass to the method.</param>
        /// <param name="parameters">Additional parameters to add to the URL.</param>
        /// <param name="additionalHeaders">Additional headers to add to the request.</param>
        /// <param name="timeout">Optional per-request timeout</param>
        /// <returns>Response body as a string.</returns>
        string InvokeMethod(
            Service service,
            Method method,
            string relativeUrl,
            string body = null,
            IDictionary<string, string> parameters = null,
            IDictionary<string, string> additionalHeaders = null,
            TimeSpan? timeout = null);

        /// <summary>
        /// Call a Safeguard API method and get a detailed response with status code, headers,
        /// and body. If there is a failure a SafeguardDotNetException will be thrown.
        /// </summary>
        /// <param name="service">Safeguard service to call.</param>
        /// <param name="method">Safeguard method type to use.</param>
        /// <param name="relativeUrl">Relative URL of the service to use.</param>
        /// <param name="body">Request body to pass to the method.</param>
        /// <param name="parameters">Additional parameters to add to the URL.</param>
        /// <param name="additionalHeaders">Additional headers to add to the request.</param>
        /// <param name="timeout">Optional per-request timeout</param>
        /// <returns>Response with status code, headers, and body as string.</returns>
        FullResponse InvokeMethodFull(
            Service service,
            Method method,
            string relativeUrl,
            string body = null,
            IDictionary<string, string> parameters = null,
            IDictionary<string, string> additionalHeaders = null,
            TimeSpan? timeout = null);

        /// <summary>
        /// Join a Safeguard for Privileged Sessions and a Safeguard appliance. The Safeguard for
        /// Privileged Sessions appliance needs to enable clustering and be a central search node.
        /// </summary>
        /// <param name="spsConnection">A connection to the SafeguardForPrivilegedSessions appliance.</param>
        /// <param name="certificateChain">The PEM certificate chain of the Safeguard web api.</param>
        /// <param name="sppAddress">The address of the Safeguard appliance.</param>
        /// <returns>Response with status code, headers, and body as string.</returns>
        FullResponse JoinSps(ISafeguardSessionsConnection spsConnection, string certificateChain, string sppAddress);

        /// <summary>
        /// Call a Safeguard API method and get any response as a CSV string. Some Safeguard API
        /// methods will return an empty body. If there is a failure a SafeguardDotNetException
        /// will be thrown.
        /// </summary>
        /// <param name="service">Safeguard service to call.</param>
        /// <param name="method">Safeguard method type to use.</param>
        /// <param name="relativeUrl">Relative URL of the service to use.</param>
        /// <param name="body">Request body to pass to the method.</param>
        /// <param name="parameters">Additional parameters to add to the URL.</param>
        /// <param name="additionalHeaders">Additional headers to add to the request.</param>
        /// <param name="timeout">Optional per-request timeout</param>
        /// <returns>Response body as a CSV string.</returns>
        string InvokeMethodCsv(
            Service service,
            Method method,
            string relativeUrl,
            string body = null,
            IDictionary<string, string> parameters = null,
            IDictionary<string, string> additionalHeaders = null,
            TimeSpan? timeout = null);

        /// <summary>
        /// Provides support for HTTP streaming requests
        /// </summary>
        IStreamingRequest Streaming { get; }

        /// <summary>
        /// Gets a Safeguard event listener. You will need to call the RegisterEventHandler()
        /// method to establish callbacks. Then, you just have to call Start().  Call Stop()
        /// when you are finished. The event listener returned by this method WILL NOT
        /// automatically recover from a SignalR timeout which occurs when there is a 30+
        /// second outage. To get an event listener that supports recovering from longer term
        /// outages, please use GetPersistentEventListener() to request a persistent event
        /// listener.
        /// </summary>
        /// <returns>The event listener.</returns>
        ISafeguardEventListener GetEventListener();

        /// <summary>
        /// Gets a persistent Safeguard event listener. You will need to call the
        /// RegisterEventHandler() method to establish callbacks. Then, you just have to
        /// call Start().  Call Stop() when you are finished. The event listener returned
        /// by this method WILL automatically recover from a SignalR timeout which occurs
        /// when there is a 30+ second outage.
        /// </summary>
        /// <returns>The persistent event listener.</returns>
        ISafeguardEventListener GetPersistentEventListener();

        /// <summary>
        /// Returns an <see cref="ISafeguardConnection"/> tailored to work with the <see cref="Service.Management"/>
        /// service. To invoke methods on the Managagement service, call this method first and use the
        /// returned ISafeguardConnection. Applicable options such as SSL validation will be inherited
        /// from the original ISafeguardConnection.
        /// </summary>
        /// <param name="networkAddress">Network address of the management service endpoint.</param>
        /// <returns>A new ISafeguardConnection configured for the Management service.</returns>
        ISafeguardConnection GetManagementServiceConnection(string networkAddress);

        /// <summary>
        /// Call Safeguard API to invalidate current access token and clear its value from
        /// the connection.  In order to continue using the connection you will need to call
        /// RefreshAccessToken().
        /// </summary>
        void LogOut();

        /// <summary>
        /// Returns a <see cref="SecureString"/> of the current access token which the caller can pass to other Safeguard
        /// methods, such as adding cluster members. Access the token value using .ToInsecureString() on the results.
        /// </summary>
        /// <returns>The current access token</returns>
        SecureString GetAccessToken();
    }
}
