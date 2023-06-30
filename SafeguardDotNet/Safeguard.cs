using System;
using System.Collections.Generic;
using System.Net.Security;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json.Linq;
using OneIdentity.SafeguardDotNet.A2A;
using OneIdentity.SafeguardDotNet.Authentication;
using OneIdentity.SafeguardDotNet.Event;
using RestSharp;

namespace OneIdentity.SafeguardDotNet
{
    /// <summary>
    /// This static class provides static methods for connecting to Safeguard API.
    /// </summary>
    public static class Safeguard
    {
        private const int DefaultApiVersion = 4;

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
            return new SafeguardConnection(new AnonymousAuthenticator(networkAddress, apiVersion, ignoreSsl, null));
        }

        /// <summary>
        /// Connect to Safeguard API anonymously.
        /// </summary>
        /// <returns>The connect.</returns>
        /// <param name="networkAddress">Network address.</param>
        /// <param name="validationCallback">Certificate validation callback delegate.</param>
        /// <param name="apiVersion">API version.</param>
        public static ISafeguardConnection Connect(string networkAddress, RemoteCertificateValidationCallback validationCallback, int apiVersion = DefaultApiVersion)
        {
            // Don't try to refresh access token on the anonymous connect method because it cannot be refreshed
            // So, don't use GetConnection() function above
            return new SafeguardConnection(new AnonymousAuthenticator(networkAddress, apiVersion, false, validationCallback));
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
            return new SafeguardConnection(new AccessTokenAuthenticator(networkAddress, accessToken, apiVersion, ignoreSsl, null));
        }

        /// <summary>
        /// Connect to Safeguard API using an API access token.
        /// </summary>
        /// <param name="networkAddress">Network address of Safeguard appliance.</param>
        /// <param name="accessToken">Existing API access token.</param>
        /// <param name="validationCallback">Certificate validation callback delegate.</param>
        /// <param name="apiVersion">Target API version to use.</param>
        /// <returns>Reusable Safeguard API connection.</returns>
        public static ISafeguardConnection Connect(string networkAddress, SecureString accessToken,
            RemoteCertificateValidationCallback validationCallback, int apiVersion = DefaultApiVersion)
        {
            // Don't try to refresh access token on the access token connect method because it cannot be refreshed
            // So, don't use GetConnection() function above
            return new SafeguardConnection(new AccessTokenAuthenticator(networkAddress, accessToken, apiVersion, false, validationCallback));
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
                ignoreSsl, null));
        }

        /// <summary>
        /// Connect to Safeguard API using a user name and password.
        /// </summary>
        /// <param name="networkAddress">Network address of Safeguard appliance.</param>
        /// <param name="provider">Safeguard authentication provider name (e.g. local).</param>
        /// <param name="username">User name to use for authentication.</param>
        /// <param name="password">User password to use for authentication.</param>
        /// <param name="validationCallback">Certificate validation callback delegate.</param>
        /// <param name="apiVersion">Target API version to use.</param>
        /// <returns>Reusable Safeguard API connection.</returns>
        public static ISafeguardConnection Connect(string networkAddress, string provider, string username,
            SecureString password, RemoteCertificateValidationCallback validationCallback, int apiVersion = DefaultApiVersion)
        {
            return GetConnection(new PasswordAuthenticator(networkAddress, provider, username, password, apiVersion,
                false, validationCallback));
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
                ignoreSsl, null));
        }

        /// <summary>
        /// Connect to Safeguard API using a client certificate from the certificate store.  Use PowerShell to list
        /// certificates with SHA-1 thumbprint.  PS> gci Cert:\CurrentUser\My
        /// </summary>
        /// <param name="networkAddress">Network address of Safeguard appliance.</param>
        /// <param name="certificateThumbprint">SHA-1 hash identifying a client certificate in personal (My) store.</param>
        /// <param name="validationCallback">Certificate validation callback delegate.</param>
        /// <param name="apiVersion">Target API version to use.</param>
        /// <returns>Reusable Safeguard API connection.</returns>
        public static ISafeguardConnection Connect(string networkAddress, string certificateThumbprint,
            RemoteCertificateValidationCallback validationCallback, int apiVersion = DefaultApiVersion)
        {
            return GetConnection(new CertificateAuthenticator(networkAddress, certificateThumbprint, apiVersion,
                false, validationCallback));
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
                apiVersion, ignoreSsl, null));
        }

        /// <summary>
        /// Connect to Safeguard API using a client certificate stored in a file.
        /// </summary>
        /// <param name="networkAddress">Network address of Safeguard appliance.</param>
        /// <param name="certificatePath">Path to PFX (or PKCS12) certificate file also containing private key.</param>
        /// <param name="certificatePassword">Password to decrypt the certificate file.</param>
        /// <param name="validationCallback">Certificate validation callback delegate.</param>
        /// <param name="apiVersion">Target API version to use.</param>
        /// <returns>Reusable Safeguard API connection.</returns>
        public static ISafeguardConnection Connect(string networkAddress, string certificatePath,
            SecureString certificatePassword, RemoteCertificateValidationCallback validationCallback, int apiVersion = DefaultApiVersion)
        {
            return GetConnection(new CertificateAuthenticator(networkAddress, certificatePath, certificatePassword,
                apiVersion, false, validationCallback));
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
                apiVersion, ignoreSsl, null));
        }

        /// <summary>
        /// Connect to Safeguard API using a client certificate stored in a memory.
        /// </summary>
        /// <param name="networkAddress">Network address of Safeguard appliance.</param>
        /// <param name="certificateData">Bytes containing a PFX (or PKCS12) formatted certificate and private key.</param>
        /// <param name="certificatePassword">Password to decrypt the certificate data.</param>
        /// <param name="validationCallback">Certificate validation callback delegate.</param>
        /// <param name="apiVersion">Target API version to use.</param>
        /// <returns>Reusable Safeguard API connection.</returns>
        public static ISafeguardConnection Connect(string networkAddress, IEnumerable<byte> certificateData,
            SecureString certificatePassword, RemoteCertificateValidationCallback validationCallback, int apiVersion = DefaultApiVersion)
        {
            return GetConnection(new CertificateAuthenticator(networkAddress, certificateData, certificatePassword,
                apiVersion, false, validationCallback));
        }

        /// <summary>
        /// Connect to Safeguard API using a client certificate from the certificate store.  Use PowerShell to list
        /// certificates with SHA-1 thumbprint.  PS> gci Cert:\CurrentUser\My
        /// </summary>
        /// <param name="networkAddress">Network address of Safeguard appliance.</param>
        /// <param name="certificateThumbprint">SHA-1 hash identifying a client certificate in personal (My) store.</param>
        /// <param name="provider">Safeguard authentication provider name (e.g. local).</param>
        /// <param name="apiVersion">Target API version to use.</param>
        /// <param name="ignoreSsl">Ignore server certificate validation.</param>
        /// <returns>Reusable Safeguard API connection.</returns>
        public static ISafeguardConnection Connect(string networkAddress, string certificateThumbprint, string provider,
            int apiVersion = DefaultApiVersion, bool ignoreSsl = false)
        {
            return GetConnection(new CertificateAuthenticator(networkAddress, certificateThumbprint, apiVersion,
                ignoreSsl, null, provider));
        }

        /// <summary>
        /// Connect to Safeguard API using a client certificate from the certificate store.  Use PowerShell to list
        /// certificates with SHA-1 thumbprint.  PS> gci Cert:\CurrentUser\My
        /// </summary>
        /// <param name="networkAddress">Network address of Safeguard appliance.</param>
        /// <param name="certificateThumbprint">SHA-1 hash identifying a client certificate in personal (My) store.</param>
        /// <param name="validationCallback">Certificate validation callback delegate.</param>
        /// <param name="provider">Safeguard authentication provider name (e.g. local).</param>
        /// <param name="apiVersion">Target API version to use.</param>
        /// <returns>Reusable Safeguard API connection.</returns>
        public static ISafeguardConnection Connect(string networkAddress, string certificateThumbprint,
            RemoteCertificateValidationCallback validationCallback, string provider, int apiVersion = DefaultApiVersion)
        {
            return GetConnection(new CertificateAuthenticator(networkAddress, certificateThumbprint, apiVersion,
                false, validationCallback, provider));
        }

        /// <summary>
        /// Connect to Safeguard API using a client certificate stored in a file.
        /// </summary>
        /// <param name="networkAddress">Network address of Safeguard appliance.</param>
        /// <param name="certificatePath">Path to PFX (or PKCS12) certificate file also containing private key.</param>
        /// <param name="certificatePassword">Password to decrypt the certificate file.</param>
        /// <param name="provider">Safeguard authentication provider name (e.g. local).</param>
        /// <param name="apiVersion">Target API version to use.</param>
        /// <param name="ignoreSsl">Ignore server certificate validation.</param>
        /// <returns>Reusable Safeguard API connection.</returns>
        public static ISafeguardConnection Connect(string networkAddress, string certificatePath,
            SecureString certificatePassword, string provider, int apiVersion = DefaultApiVersion, bool ignoreSsl = false)
        {
            return GetConnection(new CertificateAuthenticator(networkAddress, certificatePath, certificatePassword,
                apiVersion, ignoreSsl, null, provider));
        }

        /// <summary>
        /// Connect to Safeguard API using a client certificate stored in a file.
        /// </summary>
        /// <param name="networkAddress">Network address of Safeguard appliance.</param>
        /// <param name="certificatePath">Path to PFX (or PKCS12) certificate file also containing private key.</param>
        /// <param name="certificatePassword">Password to decrypt the certificate file.</param>
        /// <param name="validationCallback">Certificate validation callback delegate.</param>
        /// <param name="provider">Safeguard authentication provider name (e.g. local).</param>
        /// <param name="apiVersion">Target API version to use.</param>
        /// <returns>Reusable Safeguard API connection.</returns>
        public static ISafeguardConnection Connect(string networkAddress, string certificatePath,
            SecureString certificatePassword, RemoteCertificateValidationCallback validationCallback, string provider, int apiVersion = DefaultApiVersion)
        {
            return GetConnection(new CertificateAuthenticator(networkAddress, certificatePath, certificatePassword,
                apiVersion, false, validationCallback, provider));
        }

        /// <summary>
        /// Connect to Safeguard API using a client certificate stored in a memory.
        /// </summary>
        /// <param name="networkAddress">Network address of Safeguard appliance.</param>
        /// <param name="certificateData">Bytes containing a PFX (or PKCS12) formatted certificate and private key.</param>
        /// <param name="certificatePassword">Password to decrypt the certificate data.</param>
        /// <param name="provider">Safeguard authentication provider name (e.g. local).</param>
        /// <param name="apiVersion">Target API version to use.</param>
        /// <param name="ignoreSsl">Ignore server certificate validation.</param>
        /// <returns>Reusable Safeguard API connection.</returns>
        public static ISafeguardConnection Connect(string networkAddress, IEnumerable<byte> certificateData,
            SecureString certificatePassword, string provider, int apiVersion = DefaultApiVersion, bool ignoreSsl = false)
        {
            return GetConnection(new CertificateAuthenticator(networkAddress, certificateData, certificatePassword,
                apiVersion, ignoreSsl, null, provider));
        }

        /// <summary>
        /// Connect to Safeguard API using a client certificate stored in a memory.
        /// </summary>
        /// <param name="networkAddress">Network address of Safeguard appliance.</param>
        /// <param name="certificateData">Bytes containing a PFX (or PKCS12) formatted certificate and private key.</param>
        /// <param name="certificatePassword">Password to decrypt the certificate data.</param>
        /// <param name="validationCallback">Certificate validation callback delegate.</param>
        /// <param name="provider">Safeguard authentication provider name (e.g. local).</param>
        /// <param name="apiVersion">Target API version to use.</param>
        /// <returns>Reusable Safeguard API connection.</returns>
        public static ISafeguardConnection Connect(string networkAddress, IEnumerable<byte> certificateData,
            SecureString certificatePassword, RemoteCertificateValidationCallback validationCallback, string provider, int apiVersion = DefaultApiVersion)
        {
            return GetConnection(new CertificateAuthenticator(networkAddress, certificateData, certificatePassword,
                apiVersion, false, validationCallback, provider));
        }

        /// <summary>
        /// Create a persistent connection to the Safeguard API that automatically renews expired access tokens.
        /// </summary>
        /// <param name="connection">Connection to be made persistent</param>
        /// <returns>Reusable persistent Safeguard API connection</returns>
        public static ISafeguardConnection Persist(ISafeguardConnection connection)
        {
            return new PersistentSafeguardConnection(connection);
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
                    new PasswordAuthenticator(networkAddress, provider, username, password, apiVersion, ignoreSsl, null)));
            }

            /// <summary>
            /// Get a persistent event listener using a username and password credentia for authentication.
            /// </summary>
            /// <param name="networkAddress">Network address of Safeguard appliance.</param>
            /// <param name="provider">Safeguard authentication provider name (e.g. local).</param>
            /// <param name="username">User name to use for authentication.</param>
            /// <param name="password">User password to use for authentication.</param>
            /// <param name="validationCallback">Certificate validation callback delegate.</param>
            /// <param name="apiVersion">Target API version to use.</param>
            /// <returns>New persistent Safeguard event listener.</returns>
            public static ISafeguardEventListener GetPersistentEventListener(string networkAddress, string provider,
                string username, SecureString password, RemoteCertificateValidationCallback validationCallback, int apiVersion = DefaultApiVersion)
            {
                return new PersistentSafeguardEventListener(GetConnection(
                    new PasswordAuthenticator(networkAddress, provider, username, password, apiVersion, false, validationCallback)));
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
                    new CertificateAuthenticator(networkAddress, certificateThumbprint, apiVersion, ignoreSsl, null)));
            }

            /// <summary>
            /// Get a persistent event listener using a client certificate from the certificate store for authentication.
            /// Use PowerShell to list certificates with SHA-1 thumbprint.  PS> gci Cert:\CurrentUser\My
            /// </summary>
            /// <param name="networkAddress">Network address of Safeguard appliance.</param>
            /// <param name="certificateThumbprint">SHA-1 hash identifying a client certificate in personal (My) store.</param>
            /// <param name="validationCallback">Certificate validation callback delegate.</param>
            /// <param name="apiVersion">Target API version to use.</param>
            /// <returns>New persistent Safeguard event listener.</returns>
            public static ISafeguardEventListener GetPersistentEventListener(string networkAddress,
                string certificateThumbprint, RemoteCertificateValidationCallback validationCallback, int apiVersion = DefaultApiVersion)
            {
                return new PersistentSafeguardEventListener(GetConnection(
                    new CertificateAuthenticator(networkAddress, certificateThumbprint, apiVersion, false, validationCallback)));
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
                    certificateData, certificatePassword, apiVersion, ignoreSsl, null)));
            }

            /// <summary>
            /// Get a persistent event listener using a client certificate stored in memory.
            /// </summary>
            /// <param name="networkAddress">Network address of Safeguard appliance.</param>
            /// <param name="certificateData">Bytes containing a PFX (or PKCS12) formatted certificate and private key.</param>
            /// <param name="certificatePassword">Password to decrypt the certificate file.</param>
            /// <param name="validationCallback">Certificate validation callback delegate.</param>
            /// <param name="apiVersion">Target API version to use.</param>
            /// <returns>New persistent Safeguard event listener.</returns>
            public static ISafeguardEventListener GetPersistentEventListener(string networkAddress,
                IEnumerable<byte> certificateData, SecureString certificatePassword, RemoteCertificateValidationCallback validationCallback, int apiVersion = DefaultApiVersion)
            {
                return new PersistentSafeguardEventListener(GetConnection(new CertificateAuthenticator(networkAddress,
                    certificateData, certificatePassword, apiVersion, false, validationCallback)));
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
                    certificatePath, certificatePassword, apiVersion, ignoreSsl, null)));
            }

            /// <summary>
            /// Get a persistent event listener using a client certificate stored in a file.
            /// </summary>
            /// <param name="networkAddress">Network address of Safeguard appliance.</param>
            /// <param name="certificatePath">Path to PFX (or PKCS12) certificate file also containing private key.</param>
            /// <param name="certificatePassword">Password to decrypt the certificate file.</param>
            /// <param name="validationCallback">Certificate validation callback delegate.</param>
            /// <param name="apiVersion">Target API version to use.</param>
            /// <returns>New persistent Safeguard event listener.</returns>
            public static ISafeguardEventListener GetPersistentEventListener(string networkAddress,
                string certificatePath, SecureString certificatePassword, RemoteCertificateValidationCallback validationCallback, int apiVersion = DefaultApiVersion)
            {
                return new PersistentSafeguardEventListener(GetConnection(new CertificateAuthenticator(networkAddress,
                    certificatePath, certificatePassword, apiVersion, false, validationCallback)));
            }

            /// <summary>
            /// Get a persistent event listener using a client certificate from the certificate store for authentication.
            /// Use PowerShell to list certificates with SHA-1 thumbprint.  PS> gci Cert:\CurrentUser\My
            /// </summary>
            /// <param name="networkAddress">Network address of Safeguard appliance.</param>
            /// <param name="certificateThumbprint">SHA-1 hash identifying a client certificate in personal (My) store.</param>
            /// <param name="provider">Safeguard authentication provider name (e.g. local).</param>
            /// <param name="apiVersion">Target API version to use.</param>
            /// <param name="ignoreSsl">Ignore server certificate validation.</param>
            /// <returns>New persistent Safeguard event listener.</returns>
            public static ISafeguardEventListener GetPersistentEventListener(string networkAddress,
                string certificateThumbprint, string provider, int apiVersion = DefaultApiVersion, bool ignoreSsl = false)
            {
                return new PersistentSafeguardEventListener(GetConnection(
                    new CertificateAuthenticator(networkAddress, certificateThumbprint, apiVersion, ignoreSsl, null, provider)));
            }

            /// <summary>
            /// Get a persistent event listener using a client certificate from the certificate store for authentication.
            /// Use PowerShell to list certificates with SHA-1 thumbprint.  PS> gci Cert:\CurrentUser\My
            /// </summary>
            /// <param name="networkAddress">Network address of Safeguard appliance.</param>
            /// <param name="certificateThumbprint">SHA-1 hash identifying a client certificate in personal (My) store.</param>
            /// <param name="validationCallback">Certificate validation callback delegate.</param>
            /// <param name="provider">Safeguard authentication provider name (e.g. local).</param>
            /// <param name="apiVersion">Target API version to use.</param>
            /// <returns>New persistent Safeguard event listener.</returns>
            public static ISafeguardEventListener GetPersistentEventListener(string networkAddress,
                string certificateThumbprint, RemoteCertificateValidationCallback validationCallback, string provider, int apiVersion = DefaultApiVersion)
            {
                return new PersistentSafeguardEventListener(GetConnection(
                    new CertificateAuthenticator(networkAddress, certificateThumbprint, apiVersion, false, validationCallback, provider)));
            }

            /// <summary>
            /// Get a persistent event listener using a client certificate stored in memory.
            /// </summary>
            /// <param name="networkAddress">Network address of Safeguard appliance.</param>
            /// <param name="certificateData">Bytes containing a PFX (or PKCS12) formatted certificate and private key.</param>
            /// <param name="certificatePassword">Password to decrypt the certificate file.</param>
            /// <param name="provider">Safeguard authentication provider name (e.g. local).</param>
            /// <param name="apiVersion">Target API version to use.</param>
            /// <param name="ignoreSsl">Ignore server certificate validation.</param>
            /// <returns>New persistent Safeguard event listener.</returns>
            public static ISafeguardEventListener GetPersistentEventListener(string networkAddress,
                IEnumerable<byte> certificateData, SecureString certificatePassword, string provider, int apiVersion = DefaultApiVersion,
                bool ignoreSsl = false)
            {
                return new PersistentSafeguardEventListener(GetConnection(new CertificateAuthenticator(networkAddress,
                    certificateData, certificatePassword, apiVersion, ignoreSsl, null, provider)));
            }

            /// <summary>
            /// Get a persistent event listener using a client certificate stored in memory.
            /// </summary>
            /// <param name="networkAddress">Network address of Safeguard appliance.</param>
            /// <param name="certificateData">Bytes containing a PFX (or PKCS12) formatted certificate and private key.</param>
            /// <param name="certificatePassword">Password to decrypt the certificate file.</param>
            /// <param name="validationCallback">Certificate validation callback delegate.</param>
            /// <param name="provider">Safeguard authentication provider name (e.g. local).</param>
            /// <param name="apiVersion">Target API version to use.</param>
            /// <returns>New persistent Safeguard event listener.</returns>
            public static ISafeguardEventListener GetPersistentEventListener(string networkAddress,
                IEnumerable<byte> certificateData, SecureString certificatePassword, RemoteCertificateValidationCallback validationCallback, string provider, int apiVersion = DefaultApiVersion)
            {
                return new PersistentSafeguardEventListener(GetConnection(new CertificateAuthenticator(networkAddress,
                    certificateData, certificatePassword, apiVersion, false, validationCallback, provider)));
            }

            /// <summary>
            /// Get a persistent event listener using a client certificate stored in a file.
            /// </summary>
            /// <param name="networkAddress">Network address of Safeguard appliance.</param>
            /// <param name="certificatePath">Path to PFX (or PKCS12) certificate file also containing private key.</param>
            /// <param name="certificatePassword">Password to decrypt the certificate file.</param>
            /// <param name="provider">Safeguard authentication provider name (e.g. local).</param>
            /// <param name="apiVersion">Target API version to use.</param>
            /// <param name="ignoreSsl">Ignore server certificate validation.</param>
            /// <returns>New persistent Safeguard event listener.</returns>
            public static ISafeguardEventListener GetPersistentEventListener(string networkAddress,
                string certificatePath, SecureString certificatePassword, string provider, int apiVersion = DefaultApiVersion,
                bool ignoreSsl = false)
            {
                return new PersistentSafeguardEventListener(GetConnection(new CertificateAuthenticator(networkAddress,
                    certificatePath, certificatePassword, apiVersion, ignoreSsl, null, provider)));
            }

            /// <summary>
            /// Get a persistent event listener using a client certificate stored in a file.
            /// </summary>
            /// <param name="networkAddress">Network address of Safeguard appliance.</param>
            /// <param name="certificatePath">Path to PFX (or PKCS12) certificate file also containing private key.</param>
            /// <param name="certificatePassword">Password to decrypt the certificate file.</param>
            /// <param name="validationCallback">Certificate validation callback delegate.</param>
            /// <param name="provider">Safeguard authentication provider name (e.g. local).</param>
            /// <param name="apiVersion">Target API version to use.</param>
            /// <returns>New persistent Safeguard event listener.</returns>
            public static ISafeguardEventListener GetPersistentEventListener(string networkAddress,
                string certificatePath, SecureString certificatePassword, RemoteCertificateValidationCallback validationCallback, string provider, int apiVersion = DefaultApiVersion)
            {
                return new PersistentSafeguardEventListener(GetConnection(new CertificateAuthenticator(networkAddress,
                    certificatePath, certificatePassword, apiVersion, false, validationCallback, provider)));
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
                return new SafeguardA2AContext(networkAddress, certificateThumbprint, apiVersion, ignoreSsl, null);
            }

            /// <summary>
            /// Establish a Safeguard A2A context using a client certificate from the certificate store.  Use PowerShell to
            /// list certificates with SHA-1 thumbprint.  PS> gci Cert:\CurrentUser\My
            /// </summary>
            /// <param name="networkAddress">Network address of Safeguard appliance.</param>
            /// <param name="certificateThumbprint">SHA-1 hash identifying a client certificate in personal (My) store.</param>
            /// <param name="validationCallback">Certificate validation callback delegate.</param>
            /// <param name="apiVersion">Target API version to use.</param>
            /// <returns>Reusable Safeguard A2A context.</returns>
            public static ISafeguardA2AContext GetContext(string networkAddress, string certificateThumbprint, 
                RemoteCertificateValidationCallback validationCallback, int apiVersion = DefaultApiVersion)
            {
                return new SafeguardA2AContext(networkAddress, certificateThumbprint, apiVersion, false, validationCallback);
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
                return new SafeguardA2AContext(networkAddress, certificatePath, certificatePassword, apiVersion, ignoreSsl, null);
            }

            /// <summary>
            /// Establish a Safeguard A2A context using a client certificate stored in a file.
            /// </summary>
            /// <param name="networkAddress">Network address of Safeguard appliance.</param>
            /// <param name="certificatePath">Path to PFX (or PKCS12) certificate file also containing private key.</param>
            /// <param name="certificatePassword">Password to decrypt the certificate file.</param>
            /// <param name="validationCallback">Certificate validation callback delegate.</param>
            /// <param name="apiVersion">Target API version to use.</param>
            /// <returns>Reusable Safeguard A2A context.</returns>
            public static ISafeguardA2AContext GetContext(string networkAddress, string certificatePath,
                SecureString certificatePassword, RemoteCertificateValidationCallback validationCallback, int apiVersion = DefaultApiVersion)
            {
                return new SafeguardA2AContext(networkAddress, certificatePath, certificatePassword, apiVersion, false, validationCallback);
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
                return new SafeguardA2AContext(networkAddress, certificateData, certificatePassword, apiVersion, ignoreSsl, null);
            }

            /// <summary>
            /// Establish a Safeguard A2A context using a client certificate stored in memory.
            /// </summary>
            /// <param name="networkAddress">Network address of Safeguard appliance.</param>
            /// <param name="certificateData">Bytes containing a PFX (or PKCS12) formatted certificate and private key.</param>
            /// <param name="certificatePassword">Password to decrypt the certificate file.</param>
            /// <param name="validationCallback">Certificate validation callback delegate.</param>
            /// <param name="apiVersion">Target API version to use.</param>
            /// <returns>Reusable Safeguard A2A context.</returns>
            public static ISafeguardA2AContext GetContext(string networkAddress, IEnumerable<byte> certificateData,
                SecureString certificatePassword, RemoteCertificateValidationCallback validationCallback, int apiVersion = DefaultApiVersion)
            {
                return new SafeguardA2AContext(networkAddress, certificateData, certificatePassword, apiVersion, false, validationCallback);
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
                        new SafeguardA2AContext(networkAddress, certificateThumbprint, apiVersion, ignoreSsl, null), apiKey,
                            handler);
                }

                /// <summary>
                /// Get a persistent A2A event listener for Gets an A2A event listener. The handler passed in will be registered
                /// for the AssetAccountPasswordUpdated event, which is the only one supported in A2A. Uses a client certificate
                /// from the certificate store.
                /// </summary>
                /// <param name="apiKey">API key corresponding to the configured account to listen for.</param>
                /// <param name="handler">A delegate to call any time the AssetAccountPasswordUpdate event occurs.</param>
                /// <param name="networkAddress">Network address of Safeguard appliance.</param>
                /// <param name="certificateThumbprint">SHA-1 hash identifying a client certificate in personal (My) store.</param>
                /// <param name="validationCallback">Certificate validation callback delegate.</param>
                /// <param name="apiVersion">Target API version to use.</param>
                /// <returns>New persistent A2A event listener.</returns>
                public static ISafeguardEventListener GetPersistentA2AEventListener(SecureString apiKey,
                    SafeguardEventHandler handler, string networkAddress, string certificateThumbprint,
                    RemoteCertificateValidationCallback validationCallback, int apiVersion = DefaultApiVersion)
                {
                    return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, certificateThumbprint, apiVersion, false, validationCallback), apiKey,
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
                        new SafeguardA2AContext(networkAddress, certificateThumbprint, apiVersion, ignoreSsl, null), apiKeys, 
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
                /// <param name="validationCallback">Certificate validation callback delegate.</param>
                /// <param name="apiVersion">Target API version to use.</param>
                /// <returns>New persistent A2A event listener.</returns>
                public static ISafeguardEventListener GetPersistentA2AEventListener(IEnumerable<SecureString> apiKeys,
                    SafeguardEventHandler handler, string networkAddress, string certificateThumbprint,
                    RemoteCertificateValidationCallback validationCallback, int apiVersion = DefaultApiVersion)
                {
                    return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, certificateThumbprint, apiVersion, false, validationCallback), apiKeys, 
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
                            ignoreSsl, null), apiKey, handler);
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
                /// <param name="validationCallback">Certificate validation callback delegate.</param>
                /// <param name="apiVersion">Target API version to use.</param>
                /// <returns>New persistent A2A event listener.</returns>
                public static ISafeguardEventListener GetPersistentA2AEventListener(SecureString apiKey,
                    SafeguardEventHandler handler, string networkAddress, string certificatePath,
                    SecureString certificatePassword, RemoteCertificateValidationCallback validationCallback, int apiVersion = DefaultApiVersion)
                {
                    return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, certificatePath, certificatePassword, apiVersion,
                            false, validationCallback), apiKey, handler);
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
                            ignoreSsl, null), apiKeys, handler);
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
                /// <param name="validationCallback">Certificate validation callback delegate.</param>
                /// <param name="apiVersion">Target API version to use.</param>
                /// <returns>New persistent A2A event listener.</returns>
                public static ISafeguardEventListener GetPersistentA2AEventListener(IEnumerable<SecureString> apiKeys,
                    SafeguardEventHandler handler, string networkAddress, string certificatePath,
                    SecureString certificatePassword, RemoteCertificateValidationCallback validationCallback, int apiVersion = DefaultApiVersion)
                {
                    return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, certificatePath, certificatePassword, apiVersion,
                            false, validationCallback), apiKeys, handler);
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
                            ignoreSsl, null), apiKey, handler);
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
                /// <param name="validationCallback">Certificate validation callback delegate.</param>
                /// <param name="apiVersion">Target API version to use.</param>
                /// <returns>New persistent A2A event listener.</returns>
                public static ISafeguardEventListener GetPersistentA2AEventListener(SecureString apiKey,
                    SafeguardEventHandler handler, string networkAddress, IEnumerable<byte> certificateData,
                    SecureString certificatePassword, RemoteCertificateValidationCallback validationCallback, int apiVersion = DefaultApiVersion)
                {
                    return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, certificateData, certificatePassword, apiVersion,
                            false, validationCallback), apiKey, handler);
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
                            ignoreSsl, null), apiKeys, handler);
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
                /// <param name="validationCallback">Certificate validation callback delegate.</param>
                /// <param name="apiVersion">Target API version to use.</param>
                /// <returns>New persistent A2A event listener.</returns>
                public static ISafeguardEventListener GetPersistentA2AEventListener(IEnumerable<SecureString> apiKeys,
                    SafeguardEventHandler handler, string networkAddress, IEnumerable<byte> certificateData,
                    SecureString certificatePassword, RemoteCertificateValidationCallback validationCallback, int apiVersion = DefaultApiVersion)
                {
                    return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, certificateData, certificatePassword, apiVersion,
                            false, validationCallback), apiKeys, handler);
                }
            }
        }

        public static SecureString PostAuthorizationCodeFlow(string appliance, Tuple<string, string> authorizationCode, string RedirectUri)
        {
            var safeguardRstsUrl = $"https://{appliance}/RSTS";
            var rstsClient = new RestClient(safeguardRstsUrl,
                options =>
                {
                    // The client would have already ignored certificate validation manually in the browser
                    options.RemoteCertificateValidationCallback = (sender, certificate, chain, errors) => true;
                });

            var request = new RestRequest("oauth2/token", RestSharp.Method.Post)
                .AddHeader("Accept", "application/json")
                .AddHeader("Content-type", "application/json")
                .AddJsonBody(new
                {
                    grant_type = "authorization_code",
                    redirect_uri = RedirectUri,
                    code = authorizationCode.Item1,
                    code_verifier = authorizationCode.Item2
                });

            var response = rstsClient.Execute(request);

            if (response.ResponseStatus != ResponseStatus.Completed)
            {
                throw new SafeguardDotNetException($"Unable to connect to RSTS service {rstsClient.Options.BaseUrl}, Error: " + response.ErrorMessage);
            }

            if (!response.IsSuccessful)
            {
                throw new SafeguardDotNetException("Error using authorization code grant_type, Error: " + $"{response.StatusCode} {response.Content}", response.StatusCode, response.Content);
            }

            var jObject = JObject.Parse(response.Content);
            return jObject.GetValue("access_token")?.ToString().ToSecureString();
        }

        public static JObject PostLoginResponse(string appliance, SecureString rstsAccessToken)
        {
            var safeguardCoreUrl = $"https://{appliance}/service/core/v{DefaultApiVersion}";

            var coreClient = new RestClient(safeguardCoreUrl,
                options =>
                {
                    // The client would have already ignored certificate validation manually in the browser
                    options.RemoteCertificateValidationCallback = (sender, certificate, chain, errors) => true;
                });

            var request = new RestRequest("Token/LoginResponse", RestSharp.Method.Post)
                .AddHeader("Accept", "application/json")
                .AddHeader("Content-type", "application/json")
                .AddJsonBody(new
                {
                    StsAccessToken = rstsAccessToken.ToInsecureString()
                });

            var response = coreClient.Execute(request);

            if (response.ResponseStatus != ResponseStatus.Completed && response.ResponseStatus != ResponseStatus.Error)
            {
                throw new SafeguardDotNetException($"Unable to connect to core service {coreClient.Options.BaseUrl}, Error: " + response.ErrorMessage);
            }

            if (!response.IsSuccessful)
            {
                throw new SafeguardDotNetException("Error using authorization code grant_type, Error: " + $"{response.StatusCode} {response.Content}", response.StatusCode, response.Content);
            }

            return JObject.Parse(response.Content);
        }

        public static string OAuthCodeVerifier()
        {
            var bytes = new byte[60];
            RandomNumberGenerator.Create().GetBytes(bytes);
            return ToBase64Url(bytes);
        }

        public static string OAuthCodeChallenge(string codeVerifier)
        {
            using (var sha = SHA256.Create())
            {
                var hash = sha.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier));

                return ToBase64Url(hash);
            }
        }

        // https://172.21.21.1/RSTS/Login?
        // response_type=code&
        // redirect_uri=https%3a%2f%2flocalhost%3a7035%2f%3fserver%3d172.21.21.1%26auth%3dresume&
        // code_challenge=Ullteua8nkpbqkCUpKSxqPfTqrZvZfnmpV3YTGEPUfQ&
        // code_challenge_method=S256&
        // state=w5mtmJUPPMhHEW-qo4PyyX4pGDsevgTN2QNRC0aWiaxd8weEQdgiHoieLe4NDeuAkL63Q6-ipG1nIOwY

        /// <summary>Creates a Base64 string with the trailing equal signs removed and any plus signs replaced with
        /// minus signs and any forward slashes replaced with underscores.</summary>
        /// <param name="data">Any byte array to be Base64 encoded.</param>
        /// <returns>A special Base64 string that is URL safe. Used in JWTs, OAuth2.0 and other things.</returns>
        public static string ToBase64Url(byte[] data)
        {
            return Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }
    }
}
