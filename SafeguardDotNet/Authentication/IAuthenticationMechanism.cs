using System.Security;

namespace OneIdentity.SafeguardDotNet.Authentication
{
    internal interface IAuthenticationMechanism
    {
        string NetworkAddress { get; }

        int ApiVersion { get; }

        bool IgnoreSsl { get; }

        bool HasAccessToken();

        SecureString GetAccessToken();

        int GetAccessTokenLifetimeRemaining();

        void RefreshAccessToken();
    }
}
