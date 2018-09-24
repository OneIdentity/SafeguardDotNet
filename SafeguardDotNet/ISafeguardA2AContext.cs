using System.Security;

namespace OneIdentity.SafeguardDotNet
{
    public interface ISafeguardA2AContext
    {
        SecureString RetrievePassword(string apiKey);
    }
}
