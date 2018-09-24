using System.Security;

namespace OneIdentity.SafeguardDotNet
{
    /// <summary>
    /// This is a reusable interface for calling Safeguard A2A without having to continually
    /// pass the client certificate authentication information.
    /// </summary>
    public interface ISafeguardA2AContext
    {
        SecureString RetrievePassword(string apiKey);
    }
}
