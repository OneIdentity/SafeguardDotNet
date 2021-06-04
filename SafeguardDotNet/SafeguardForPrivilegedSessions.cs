using System.Collections.Generic;
using System.Net.Security;
using System.Security;
using OneIdentity.SafeguardDotNet.A2A;
using OneIdentity.SafeguardDotNet.Authentication;
using OneIdentity.SafeguardDotNet.Event;

namespace OneIdentity.SafeguardDotNet
{
    /// <summary>
    /// This static class provides static methods for connecting to Safeguard for Privileged Sessions API.
    /// </summary>
    public static class SafeguardForPrivilegedSessions
    {
        /// <summary>
        /// Connect to Safeguard for Privileged Sessions API using a user name and password.
        /// </summary>
        /// <param name="networkAddress">Network address of Safeguard for Privileged Sessions appliance.</param>
        /// <param name="username">User name to use for authentication.</param>
        /// <param name="password">User password to use for authentication.</param>
        /// <param name="ignoreSsl">Ignore server certificate validation.</param>
        /// <returns>Reusable Safeguard for Privileged Sessions API connection.</returns>
        public static ISafeguardSessionsConnection Connect(string networkAddress, string username,
            SecureString password, bool ignoreSsl = false)
        {
            return new SafeguardSessionsConnection(networkAddress, username, password, ignoreSsl);
        }
    }
}
