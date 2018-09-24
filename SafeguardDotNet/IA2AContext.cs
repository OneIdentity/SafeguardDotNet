using System.Security;

namespace OneIdentity.SafeguardDotNet
{
    public interface IA2AContext
    {
        SecureString RetrievePassword(string apiKey);
    }
}
