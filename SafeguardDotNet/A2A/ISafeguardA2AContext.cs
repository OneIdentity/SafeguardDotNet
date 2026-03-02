// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.A2A
{
    using System;
    using System.Collections.Generic;
    using System.Security;

    using OneIdentity.SafeguardDotNet.Event;

    /// <summary>
    /// This is a reusable interface for calling Safeguard A2A without having to continually
    /// pass the client certificate authentication information.
    /// </summary>
    public interface ISafeguardA2AContext : IDisposable
    {
        /// <summary>
        /// Retrieves the list of retrievable accounts for this A2A context.  Listing the retrievable accounts is a
        /// new feature for Safeguard v2.8+, and it needs to be enabled in the A2A configuration.
        /// </summary>
        /// <returns>A list of retrievable accounts.</returns>
        IList<A2ARetrievableAccount> GetRetrievableAccounts();

        /// <summary>
        /// Retrieves a password using Safeguard A2A.
        /// </summary>
        /// <param name="apiKey">API key corresponding to the configured account.</param>
        /// <returns>The password.</returns>
        SecureString RetrievePassword(SecureString apiKey);

        /// <summary>
        /// Sets a password using Safeguard A2A.
        /// </summary>
        /// <param name="apiKey">API key corresponding to the configured account.</param>
        /// <param name="password">Password to set.</param>
        /// <returns></returns>
        void SetPassword(SecureString apiKey, SecureString password);

        /// <summary>
        /// Retrieves an SSH private key using Safeguard A2A.
        /// </summary>
        /// <param name="apiKey">API key corresponding to the configured account.</param>
        /// <param name="keyFormat">Format to use when returning private key.</param>
        /// <returns>The SSH private key.</returns>
        SecureString RetrievePrivateKey(SecureString apiKey, KeyFormat keyFormat = KeyFormat.OpenSsh);

        /// <summary>
        /// Sets an SSH private key using Safeguard A2A.
        /// </summary>
        /// <param name="apiKey">API key corresponding to the configured account.</param>
        /// <param name="privateKey">Private key to set.</param>
        /// <param name="password">Password associated with the private key.</param>
        /// <param name="keyFormat">Format to use when returning private key.</param>
        /// <returns>The SSH private key.</returns>
        void SetPrivateKey(SecureString apiKey, SecureString privateKey, SecureString password, KeyFormat keyFormat = KeyFormat.OpenSsh);

        /// <summary>
        /// Retrieves an API key secret using Safeguard A2A.
        /// </summary>
        /// <param name="apiKey">API key corresponding to the configured account.</param>
        /// <returns>A list of API key secrets.</returns>
        IList<ApiKeySecret> RetrieveApiKeySecret(SecureString apiKey);

        /// <summary>
        /// Gets an A2A event listener. The handler passed in will be registered for the AssetAccountPasswordUpdated
        /// event, which is the only one supported in A2A. You just have to call Start(). The event listener returned
        /// by this method WILL NOT automatically recover from a SignalR timeout which occurs when there is a 30+
        /// second outage. To get an event listener that supports recovering from longer term outages, please use
        /// GetPersistentEventListener() to request a persistent event listener.
        /// </summary>
        /// <param name="apiKey">API key corresponding to the configured account to listen for.</param>
        /// <param name="handler">A delegate to call any time the AssetAccountPasswordUpdate event occurs.</param>
        /// <returns>The event listener.</returns>
        ISafeguardEventListener GetA2AEventListener(SecureString apiKey, SafeguardEventHandler handler);

        /// <summary>
        /// Gets an A2A event listener. The handler passed in will be registered for the AssetAccountPasswordUpdated
        /// event, which is the only one supported in A2A. You just have to call Start(). The event listener returned
        /// by this method WILL NOT automatically recover from a SignalR timeout which occurs when there is a 30+
        /// second outage. To get an event listener that supports recovering from longer term outages, please use
        /// GetPersistentEventListener() to request a persistent event listener.
        /// </summary>
        /// <param name="apiKeys">A list of API keys corresponding to the configured accounts to listen for.</param>
        /// <param name="handler">A delegate to call any time the AssetAccountPasswordUpdate event occurs.</param>
        /// <returns>The event listener.</returns>
        ISafeguardEventListener GetA2AEventListener(IEnumerable<SecureString> apiKeys, SafeguardEventHandler handler);

        /// <summary>
        /// Gets a persistent A2A event listener. The handler passed in will be registered for the
        /// AssetAccountPasswordUpdated event, which is the only one supported in A2A. You just have to call Start().
        /// The event listener returned by this method WILL automatically recover from a SignalR timeout which
        /// occurs when there is a 30+ second outage.
        /// </summary>
        /// <param name="apiKey">API key corresponding to the configured account to listen for.</param>
        /// <param name="handler">A delegate to call any time the AssetAccountPasswordUpdate event occurs.</param>
        /// <returns>The event listener.</returns>
        ISafeguardEventListener GetPersistentA2AEventListener(SecureString apiKey, SafeguardEventHandler handler);

        /// <summary>
        /// Gets a persistent A2A event listener. The handler passed in will be registered for the
        /// AssetAccountPasswordUpdated event, which is the only one supported in A2A. You just have to call Start().
        /// The event listener returned by this method WILL automatically recover from a SignalR timeout which
        /// occurs when there is a 30+ second outage.
        /// </summary>
        /// <param name="apiKeys">A list of API keys corresponding to the configured accounts to listen for.</param>
        /// <param name="handler">A delegate to call any time the AssetAccountPasswordUpdate event occurs.</param>
        /// <returns>The event listener.</returns>
        ISafeguardEventListener GetPersistentA2AEventListener(IEnumerable<SecureString> apiKeys, SafeguardEventHandler handler);

        /// <summary>
        /// Creates an access request on behalf of another user using Safeguard A2A.
        /// </summary>
        /// <param name="apiKey">API key corresponding to the access request broker.</param>
        /// <param name="accessRequest">The details of the access request to create.</param>
        /// <returns>A JSON string representing the new access request.</returns>
        string BrokerAccessRequest(SecureString apiKey, BrokeredAccessRequest accessRequest);
    }
}
