// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.Sps
{
    using System.Security;

    /// <summary>
    /// This static class provides static methods for connecting to the Safeguard for Privileged Sessions API.
    /// </summary>
    public static class SafeguardForPrivilegedSessions
    {
        /// <summary>
        /// Connect to the Safeguard for Privileged Sessions API using a user name and password.
        /// </summary>
        /// <param name="networkAddress">Network address of Safeguard for Privileged Sessions appliance.</param>
        /// <param name="username">User name to use for authentication.</param>
        /// <param name="password">User password to use for authentication.</param>
        /// <param name="ignoreSsl">Ignore server certificate validation.</param>
        /// <returns>Reusable Safeguard for Privileged Sessions API connection.</returns>
        public static ISafeguardSessionsConnection Connect(string networkAddress, string username, SecureString password, bool ignoreSsl = false)
        {
            return new SafeguardSessionsConnection(new SpsAuthenticator(networkAddress, username, password, ignoreSsl));
        }
    }
}
