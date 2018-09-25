using System.Security;

namespace OneIdentity.SafeguardDotNet
{
    /// <summary>
    /// This is a reusable interface for calling Safeguard A2A without having to continually
    /// pass the client certificate authentication information.
    /// </summary>
    public interface ISafeguardA2AContext
    {
        /// <summary>
        /// Retrieves a password using Safeguard A2A.
        /// </summary>
        /// <param name="apiKey">API key corresponding to the configured account.</param>
        /// <returns>The password.</returns>
        SecureString RetrievePassword(string apiKey);
    }
}
