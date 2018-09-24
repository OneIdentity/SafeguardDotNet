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
            // So, don't use GetConnection() function above
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

        public static class A2A
        {
            public static IA2AContext GetContext(string networkAddress, string certificateThumbprint,
                int apiVersion = DefaultApiVersion, bool ignoreSsl = false)
            {
                return new A2AContext(networkAddress, certificateThumbprint, apiVersion, ignoreSsl);
            }

            public static IA2AContext GetContext(string networkAddress, string certificatePath,
                SecureString certificatePassword, int apiVersion = DefaultApiVersion, bool ignoreSsl = false)
            {
                return new A2AContext(networkAddress, certificatePath, certificatePassword, apiVersion, ignoreSsl);
            }

            public static SecureString RetrievePassword(string networkAddress, string certificateThumbprint,
                string apiKey, int apiVersion = DefaultApiVersion, bool ignoreSsl = false)
            {
                return GetContext(networkAddress, certificateThumbprint, apiVersion, ignoreSsl)
                    .RetrievePassword(apiKey);
            }

            public static SecureString RetrievePassword(string networkAddress, string certificatePath,
                SecureString certificatePassword, string apiKey, int apiVersion = DefaultApiVersion,
                bool ignoreSsl = false)
            {
                return GetContext(networkAddress, certificatePath, certificatePassword, apiVersion, ignoreSsl)
                    .RetrievePassword(apiKey);
            }
        }
    }
}
