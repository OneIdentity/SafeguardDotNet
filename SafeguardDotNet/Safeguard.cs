using System.Security;
using OneIdentity.SafeguardDotNet.Authentication;

namespace OneIdentity.SafeguardDotNet
{
    public static class Safeguard
    {
        private const int DefaultApiVersion = 2;

        private static SafeguardConnection GetConnection(IAuthenticationMechanism authenticationMechanism)
        {
            authenticationMechanism.RefreshAccessToken();
            return new SafeguardConnection(authenticationMechanism);
        }

        public static ISafeguardConnection Connect(string networkAddress, SecureString accessToken,
            int apiVersion = DefaultApiVersion, bool ignoreSsl = false)
        {
            // Don't try to refresh access token on the acceess token connect method because it cannot be refreshed
            return new SafeguardConnection(new AccessTokenAuthenticator(networkAddress, accessToken, apiVersion, ignoreSsl));
        }

        public static ISafeguardConnection Connect(string networkAddress, string provider, string username,
            SecureString password, int apiVersion = DefaultApiVersion, bool ignoreSsl = false)
        {
            return GetConnection(new PasswordAuthenticator(networkAddress, provider, username, password, apiVersion,
                ignoreSsl));
        }

        public static ISafeguardConnection Connect(string networkAddress, string certificateThumbprint,
            int apiVersion = DefaultApiVersion, bool ignoreSsl = false)
        {
            return GetConnection(new CertificateAuthenticator(networkAddress, certificateThumbprint, apiVersion,
                ignoreSsl));
        }

        public static ISafeguardConnection Connect(string networkAddress, string certificatePath,
            SecureString certificatePassword, int apiVersion = DefaultApiVersion, bool ignoreSsl = false)
        {
            return GetConnection(new CertificateAuthenticator(networkAddress, certificatePath, certificatePassword,
                apiVersion, ignoreSsl));
        }
    }
}
