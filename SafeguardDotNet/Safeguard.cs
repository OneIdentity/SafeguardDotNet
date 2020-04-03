using System.Collections.Generic;
using System.Security;
using OneIdentity.SafeguardDotNet.A2A;
using OneIdentity.SafeguardDotNet.Authentication;
using OneIdentity.SafeguardDotNet.Event;

namespace OneIdentity.SafeguardDotNet
{
    /// <summary>
    /// This static class provides static methods for connecting to Safeguard API.
    /// </summary>
    public static class Safeguard
    {
        private const int DefaultApiVersion = 3;

        private static SafeguardConnection GetConnection(IAuthenticationMechanism authenticationMechanism)
        {
            authenticationMechanism.RefreshAccessToken();
            return new SafeguardConnection(authenticationMechanism);
        }

        /// <summary>
        /// Connect to Safeguard API anonymously.
        /// </summary>
        /// <returns>The connect.</returns>
        /// <param name="networkAddress">Network address.</param>
        /// <param name="apiVersion">API version.</param>
        /// <param name="ignoreSsl">If set to <c>true</c> ignore ssl.</param>
        public static ISafeguardConnection Connect(string networkAddress, int apiVersion = DefaultApiVersion, bool ignoreSsl = false)
        {
            // Don't try to refresh access token on the anonymous connect method because it cannot be refreshed
            // So, don't use GetConnection() function above
            return new SafeguardConnection(new AnonymousAuthenticator(networkAddress, apiVersion, ignoreSsl));
        }

        /// <summary>
        /// Connect to Safeguard API using an API access token.
        /// </summary>
        /// <param name="networkAddress">Network address of Safeguard appliance.</param>
        /// <param name="accessToken">Existing API access token.</param>
        /// <param name="apiVersion">Target API version to use.</param>
        /// <param name="ignoreSsl">Ignore server certificate validation.</param>
        /// <returns>Reusable Safeguard API connection.</returns>
        public static ISafeguardConnection Connect(string networkAddress, SecureString accessToken,
            int apiVersion = DefaultApiVersion, bool ignoreSsl = false)
        {
            // Don't try to refresh access token on the access token connect method because it cannot be refreshed
            // So, don't use GetConnection() function above
            return new SafeguardConnection(new AccessTokenAuthenticator(networkAddress, accessToken, apiVersion, ignoreSsl));
        }

        /// <summary>
        /// Connect to Safeguard API using a user name and password.
        /// </summary>
        /// <param name="networkAddress">Network address of Safeguard appliance.</param>
        /// <param name="provider">Safeguard authentication provider name (e.g. local).</param>
        /// <param name="username">User name to use for authentication.</param>
        /// <param name="password">User password to use for authentication.</param>
        /// <param name="apiVersion">Target API version to use.</param>
        /// <param name="ignoreSsl">Ignore server certificate validation.</param>
        /// <returns>Reusable Safeguard API connection.</returns>
        public static ISafeguardConnection Connect(string networkAddress, string provider, string username,
            SecureString password, int apiVersion = DefaultApiVersion, bool ignoreSsl = false)
        {
            return GetConnection(new PasswordAuthenticator(networkAddress, provider, username, password, apiVersion,
                ignoreSsl));
        }

        /// <summary>
        /// Connect to Safeguard API using a client certificate from the certificate store.  Use PowerShell to list
        /// certificates with SHA-1 thumbprint.  PS> gci Cert:\CurrentUser\My
        /// </summary>
        /// <param name="networkAddress">Network address of Safeguard appliance.</param>
        /// <param name="certificateThumbprint">SHA-1 hash identifying a client certificate in personal (My) store.</param>
        /// <param name="apiVersion">Target API version to use.</param>
        /// <param name="ignoreSsl">Ignore server certificate validation.</param>
        /// <returns>Reusable Safeguard API connection.</returns>
        public static ISafeguardConnection Connect(string networkAddress, string certificateThumbprint,
            int apiVersion = DefaultApiVersion, bool ignoreSsl = false)
        {
            return GetConnection(new CertificateAuthenticator(networkAddress, certificateThumbprint, apiVersion,
                ignoreSsl));
        }

        /// <summary>
        /// Connect to Safeguard API using a client certificate stored in a file.
        /// </summary>
        /// <param name="networkAddress">Network address of Safeguard appliance.</param>
        /// <param name="certificatePath">Path to PFX (or PKCS12) certificate file also containing private key.</param>
        /// <param name="certificatePassword">Password to decrypt the certificate file.</param>
        /// <param name="apiVersion">Target API version to use.</param>
        /// <param name="ignoreSsl">Ignore server certificate validation.</param>
        /// <returns>Reusable Safeguard API connection.</returns>
        public static ISafeguardConnection Connect(string networkAddress, string certificatePath,
            SecureString certificatePassword, int apiVersion = DefaultApiVersion, bool ignoreSsl = false)
        {
            return GetConnection(new CertificateAuthenticator(networkAddress, certificatePath, certificatePassword,
                apiVersion, ignoreSsl));
        }

        /// <summary>
        /// Connect to Safeguard API using a client certificate stored in a memory.
        /// </summary>
        /// <param name="networkAddress">Network address of Safeguard appliance.</param>
        /// <param name="certificateData">Bytes containing a PFX (or PKCS12) formatted certificate and private key.</param>
        /// <param name="certificatePassword">Password to decrypt the certificate data.</param>
        /// <param name="apiVersion">Target API version to use.</param>
        /// <param name="ignoreSsl">Ignore server certificate validation.</param>
        /// <returns>Reusable Safeguard API connection.</returns>
        public static ISafeguardConnection Connect(string networkAddress, IEnumerable<byte> certificateData,
            SecureString certificatePassword, int apiVersion = DefaultApiVersion, bool ignoreSsl = false)
        {
            return GetConnection(new CertificateAuthenticator(networkAddress, certificateData, certificatePassword,
                apiVersion, ignoreSsl));
        }

        /// <summary>
        /// This static class provides access to Safeguard Event functionality with persistent event listeners. Persistent
        /// event listeners can handle longer term service outages to reconnect SignalR even after it times out. It is
        /// recommended to use these interfaces when listening for Safeguard events from a long-running service.
        /// </summary>
        public static class Event
        {
            /// <summary>
            /// Get a persistent event listener using a username and password credentia for authentication.
            /// </summary>
            /// <param name="networkAddress">Network address of Safeguard appliance.</param>
            /// <param name="provider">Safeguard authentication provider name (e.g. local).</param>
            /// <param name="username">User name to use for authentication.</param>
            /// <param name="password">User password to use for authentication.</param>
            /// <param name="apiVersion">Target API version to use.</param>
            /// <param name="ignoreSsl">Ignore server certificate validation.</param>
            /// <returns>New persistent Safeguard event listener.</returns>
            public static ISafeguardEventListener GetPersistentEventListener(string networkAddress, string provider,
                string username, SecureString password, int apiVersion = DefaultApiVersion, bool ignoreSsl = false)
            {
                return new PersistentSafeguardEventListener(GetConnection(
                    new PasswordAuthenticator(networkAddress, provider, username, password, apiVersion, ignoreSsl)));
            }

            /// <summary>
            /// Get a persistent event listener using a client certificate from the certificate store for authentication.
            /// Use PowerShell to list certificates with SHA-1 thumbprint.  PS> gci Cert:\CurrentUser\My
            /// </summary>
            /// <param name="networkAddress">Network address of Safeguard appliance.</param>
            /// <param name="certificateThumbprint">SHA-1 hash identifying a client certificate in personal (My) store.</param>
            /// <param name="apiVersion">Target API version to use.</param>
            /// <param name="ignoreSsl">Ignore server certificate validation.</param>
            /// <returns>New persistent Safeguard event listener.</returns>
            public static ISafeguardEventListener GetPersistentEventListener(string networkAddress,
                string certificateThumbprint, int apiVersion = DefaultApiVersion, bool ignoreSsl = false)
            {
                return new PersistentSafeguardEventListener(GetConnection(
                    new CertificateAuthenticator(networkAddress, certificateThumbprint, apiVersion, ignoreSsl)));
            }

            /// <summary>
            /// Get a persistent event listener using a client certificate stored in memory.
            /// </summary>
            /// <param name="networkAddress">Network address of Safeguard appliance.</param>
            /// <param name="certificateData">Bytes containing a PFX (or PKCS12) formatted certificate and private key.</param>
            /// <param name="certificatePassword">Password to decrypt the certificate file.</param>
            /// <param name="apiVersion">Target API version to use.</param>
            /// <param name="ignoreSsl">Ignore server certificate validation.</param>
            /// <returns>New persistent Safeguard event listener.</returns>
            public static ISafeguardEventListener GetPersistentEventListener(string networkAddress,
                IEnumerable<byte> certificateData, SecureString certificatePassword, int apiVersion = DefaultApiVersion,
                bool ignoreSsl = false)
            {
                return new PersistentSafeguardEventListener(GetConnection(new CertificateAuthenticator(networkAddress,
                    certificateData, certificatePassword, apiVersion, ignoreSsl)));
            }

            /// <summary>
            /// Get a persistent event listener using a client certificate stored in a file.
            /// </summary>
            /// <param name="networkAddress">Network address of Safeguard appliance.</param>
            /// <param name="certificatePath">Path to PFX (or PKCS12) certificate file also containing private key.</param>
            /// <param name="certificatePassword">Password to decrypt the certificate file.</param>
            /// <param name="apiVersion">Target API version to use.</param>
            /// <param name="ignoreSsl">Ignore server certificate validation.</param>
            /// <returns>New persistent Safeguard event listener.</returns>
            public static ISafeguardEventListener GetPersistentEventListener(string networkAddress,
                string certificatePath, SecureString certificatePassword, int apiVersion = DefaultApiVersion,
                bool ignoreSsl = false)
            {
                return new PersistentSafeguardEventListener(GetConnection(new CertificateAuthenticator(networkAddress,
                    certificatePath, certificatePassword, apiVersion, ignoreSsl)));
            }
        }

        /// <summary>
        /// This static class provides access to Safeguard A2A functionality.
        /// </summary>
        public static class A2A
        {
            /// <summary>
            /// Establish a Safeguard A2A context using a client certificate from the certificate store.  Use PowerShell to
            /// list certificates with SHA-1 thumbprint.  PS> gci Cert:\CurrentUser\My
            /// </summary>
            /// <param name="networkAddress">Network address of Safeguard appliance.</param>
            /// <param name="certificateThumbprint">SHA-1 hash identifying a client certificate in personal (My) store.</param>
            /// <param name="apiVersion">Target API version to use.</param>
            /// <param name="ignoreSsl">Ignore server certificate validation.</param>
            /// <returns>Reusable Safeguard A2A context.</returns>
            public static ISafeguardA2AContext GetContext(string networkAddress, string certificateThumbprint,
                int apiVersion = DefaultApiVersion, bool ignoreSsl = false)
            {
                return new SafeguardA2AContext(networkAddress, certificateThumbprint, apiVersion, ignoreSsl);
            }

            /// <summary>
            /// Establish a Safeguard A2A context using a client certificate stored in a file.
            /// </summary>
            /// <param name="networkAddress">Network address of Safeguard appliance.</param>
            /// <param name="certificatePath">Path to PFX (or PKCS12) certificate file also containing private key.</param>
            /// <param name="certificatePassword">Password to decrypt the certificate file.</param>
            /// <param name="apiVersion">Target API version to use.</param>
            /// <param name="ignoreSsl">Ignore server certificate validation.</param>
            /// <returns>Reusable Safeguard A2A context.</returns>
            public static ISafeguardA2AContext GetContext(string networkAddress, string certificatePath,
                SecureString certificatePassword, int apiVersion = DefaultApiVersion, bool ignoreSsl = false)
            {
                return new SafeguardA2AContext(networkAddress, certificatePath, certificatePassword, apiVersion, ignoreSsl);
            }

            /// <summary>
            /// Establish a Safeguard A2A context using a client certificate stored in memory.
            /// </summary>
            /// <param name="networkAddress">Network address of Safeguard appliance.</param>
            /// <param name="certificateData">Bytes containing a PFX (or PKCS12) formatted certificate and private key.</param>
            /// <param name="certificatePassword">Password to decrypt the certificate file.</param>
            /// <param name="apiVersion">Target API version to use.</param>
            /// <param name="ignoreSsl">Ignore server certificate validation.</param>
            /// <returns>Reusable Safeguard A2A context.</returns>
            public static ISafeguardA2AContext GetContext(string networkAddress, IEnumerable<byte> certificateData,
                SecureString certificatePassword, int apiVersion = DefaultApiVersion, bool ignoreSsl = false)
            {
                return new SafeguardA2AContext(networkAddress, certificateData, certificatePassword, apiVersion, ignoreSsl);
            }

            /// <summary>
            /// This static class provides access to Safeguard A2A Event functionality with persistent event listeners. Persistent
            /// event listeners can handle longer term service outages to reconnect SignalR even after it times out. It is
            /// recommended to use these interfaces when listening for Safeguard events from a long-running service.
            /// </summary>
            // ReSharper disable once MemberHidesStaticFromOuterClass
            public static class Event
            {
                /// <summary>
                /// Get a persistent A2A event listener for Gets an A2A event listener. The handler passed in will be registered
                /// for the AssetAccountPasswordUpdated event, which is the only one supported in A2A. Uses a client certificate
                /// from the certificate store.
                /// </summary>
                /// <param name="apiKey">API key corresponding to the configured account to listen for.</param>
                /// <param name="handler">A delegate to call any time the AssetAccountPasswordUpdate event occurs.</param>
                /// <param name="networkAddress">Network address of Safeguard appliance.</param>
                /// <param name="certificateThumbprint">SHA-1 hash identifying a client certificate in personal (My) store.</param>
                /// <param name="apiVersion">Target API version to use.</param>
                /// <param name="ignoreSsl">Ignore server certificate validation.</param>
                /// <returns>New persistent A2A event listener.</returns>
                public static ISafeguardEventListener GetPersistentA2AEventListener(SecureString apiKey,
                    SafeguardEventHandler handler, string networkAddress, string certificateThumbprint,
                    int apiVersion = DefaultApiVersion, bool ignoreSsl = false)
                {
                    return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, certificateThumbprint, apiVersion, ignoreSsl), apiKey,
                            handler);
                }

                /// <summary>
                /// Get a persistent A2A event listener for Gets an A2A event listener. The handler passed in will be registered
                /// for the AssetAccountPasswordUpdated event, which is the only one supported in A2A. Uses a client certificate
                /// from the certificate store.
                /// </summary>
                /// <param name="apiKeys">A list of API keys corresponding to the configured accounts to listen for.</param>
                /// <param name="handler">A delegate to call any time the AssetAccountPasswordUpdate event occurs.</param>
                /// <param name="networkAddress">Network address of Safeguard appliance.</param>
                /// <param name="certificateThumbprint">SHA-1 hash identifying a client certificate in personal (My) store.</param>
                /// <param name="apiVersion">Target API version to use.</param>
                /// <param name="ignoreSsl">Ignore server certificate validation.</param>
                /// <returns>New persistent A2A event listener.</returns>
                public static ISafeguardEventListener GetPersistentA2AEventListener(IEnumerable<SecureString> apiKeys,
                    SafeguardEventHandler handler, string networkAddress, string certificateThumbprint,
                    int apiVersion = DefaultApiVersion, bool ignoreSsl = false)
                {
                    return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, certificateThumbprint, apiVersion, ignoreSsl), apiKeys, 
                            handler);
                }

                /// <summary>
                /// Get a persistent A2A event listener for Gets an A2A event listener. The handler passed in will be registered
                /// for the AssetAccountPasswordUpdated event, which is the only one supported in A2A. Uses a client certificate
                /// stored in a file.
                /// </summary>
                /// <param name="apiKey">API key corresponding to the configured account to listen for.</param>
                /// <param name="handler">A delegate to call any time the AssetAccountPasswordUpdate event occurs.</param>
                /// <param name="networkAddress">Network address of Safeguard appliance.</param>
                /// <param name="certificatePath">Path to PFX (or PKCS12) certificate file also containing private key.</param>
                /// <param name="certificatePassword">Password to decrypt the certificate file.</param>
                /// <param name="apiVersion">Target API version to use.</param>
                /// <param name="ignoreSsl">Ignore server certificate validation.</param>
                /// <returns>New persistent A2A event listener.</returns>
                public static ISafeguardEventListener GetPersistentA2AEventListener(SecureString apiKey,
                    SafeguardEventHandler handler, string networkAddress, string certificatePath,
                    SecureString certificatePassword, int apiVersion = DefaultApiVersion, bool ignoreSsl = false)
                {
                    return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, certificatePath, certificatePassword, apiVersion,
                            ignoreSsl), apiKey, handler);
                }

                /// <summary>
                /// Get a persistent A2A event listener for Gets an A2A event listener. The handler passed in will be registered
                /// for the AssetAccountPasswordUpdated event, which is the only one supported in A2A. Uses a client certificate
                /// stored in a file.
                /// </summary>
                /// <param name="apiKeys">A list of API keys corresponding to the configured accounts to listen for.</param>
                /// <param name="handler">A delegate to call any time the AssetAccountPasswordUpdate event occurs.</param>
                /// <param name="networkAddress">Network address of Safeguard appliance.</param>
                /// <param name="certificatePath">Path to PFX (or PKCS12) certificate file also containing private key.</param>
                /// <param name="certificatePassword">Password to decrypt the certificate file.</param>
                /// <param name="apiVersion">Target API version to use.</param>
                /// <param name="ignoreSsl">Ignore server certificate validation.</param>
                /// <returns>New persistent A2A event listener.</returns>
                public static ISafeguardEventListener GetPersistentA2AEventListener(IEnumerable<SecureString> apiKeys,
                    SafeguardEventHandler handler, string networkAddress, string certificatePath,
                    SecureString certificatePassword, int apiVersion = DefaultApiVersion, bool ignoreSsl = false)
                {
                    return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, certificatePath, certificatePassword, apiVersion,
                            ignoreSsl), apiKeys, handler);
                }

                /// <summary>
                /// Get a persistent A2A event listener for Gets an A2A event listener. The handler passed in will be registered
                /// for the AssetAccountPasswordUpdated event, which is the only one supported in A2A. Uses a client certificate
                /// stored in memory.
                /// </summary>
                /// <param name="apiKey">API key corresponding to the configured account to listen for.</param>
                /// <param name="handler">A delegate to call any time the AssetAccountPasswordUpdate event occurs.</param>
                /// <param name="networkAddress">Network address of Safeguard appliance.</param>
                /// <param name="certificateData">Bytes containing a PFX (or PKCS12) formatted certificate and private key.</param>
                /// <param name="certificatePassword">Password to decrypt the certificate file.</param>
                /// <param name="apiVersion">Target API version to use.</param>
                /// <param name="ignoreSsl">Ignore server certificate validation.</param>
                /// <returns>New persistent A2A event listener.</returns>
                public static ISafeguardEventListener GetPersistentA2AEventListener(SecureString apiKey,
                    SafeguardEventHandler handler, string networkAddress, IEnumerable<byte> certificateData,
                    SecureString certificatePassword, int apiVersion = DefaultApiVersion, bool ignoreSsl = false)
                {
                    return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, certificateData, certificatePassword, apiVersion,
                            ignoreSsl), apiKey, handler);
                }

                /// <summary>
                /// Get a persistent A2A event listener for Gets an A2A event listener. The handler passed in will be registered
                /// for the AssetAccountPasswordUpdated event, which is the only one supported in A2A. Uses a client certificate
                /// stored in memory.
                /// </summary>
                /// <param name="apiKeys">A list of API keys corresponding to the configured accounts to listen for.</param>
                /// <param name="handler">A delegate to call any time the AssetAccountPasswordUpdate event occurs.</param>
                /// <param name="networkAddress">Network address of Safeguard appliance.</param>
                /// <param name="certificateData">Bytes containing a PFX (or PKCS12) formatted certificate and private key.</param>
                /// <param name="certificatePassword">Password to decrypt the certificate file.</param>
                /// <param name="apiVersion">Target API version to use.</param>
                /// <param name="ignoreSsl">Ignore server certificate validation.</param>
                /// <returns>New persistent A2A event listener.</returns>
                public static ISafeguardEventListener GetPersistentA2AEventListener(IEnumerable<SecureString> apiKeys,
                    SafeguardEventHandler handler, string networkAddress, IEnumerable<byte> certificateData,
                    SecureString certificatePassword, int apiVersion = DefaultApiVersion, bool ignoreSsl = false)
                {
                    return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, certificateData, certificatePassword, apiVersion,
                            ignoreSsl), apiKeys, handler);
                }
            }
        }
    }
}
