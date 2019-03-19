using System;
using System.Security;

namespace OneIdentity.SafeguardDotNet.Authentication
{
    internal interface IAuthenticationMechanism : IDisposable, ICloneable
    {
        string NetworkAddress { get; }

        int ApiVersion { get; }

        bool IgnoreSsl { get; }

        bool HasAccessToken();

        void ClearAccessToken();

        SecureString GetAccessToken();

        int GetAccessTokenLifetimeRemaining();

        void RefreshAccessToken();
    }
}
