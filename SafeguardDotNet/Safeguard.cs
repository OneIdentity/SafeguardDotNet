// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet
{
    using System;
    using System.Collections.Generic;
    using System.Net.Http;
    using System.Net.Security;
    using System.Security;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;

    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;

    using OneIdentity.SafeguardDotNet.A2A;
    using OneIdentity.SafeguardDotNet.Authentication;
    using OneIdentity.SafeguardDotNet.Event;

    /// <summary>
    /// This static class provides static methods for connecting to Safeguard API.
    /// </summary>
    public static class Safeguard
    {
        /// <summary>
        /// Default Safeguard API version (v4). This version is used by default across all connection methods
        /// unless explicitly overridden. API v4 is supported in Safeguard 7.0 and later.
        /// </summary>
        public const int DefaultApiVersion = 4;

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
        public static ISafeguardConnection Connect(
            string networkAddress,
            SecureString accessToken,
            int apiVersion = DefaultApiVersion,
            bool ignoreSsl = false)
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
        public static ISafeguardConnection Connect(
            string networkAddress,
            SecureString accessToken,
            RemoteCertificateValidationCallback validationCallback,
            int apiVersion = DefaultApiVersion)
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
        public static ISafeguardConnection Connect(
            string networkAddress,
            string provider,
            string username,
            SecureString password,
            int apiVersion = DefaultApiVersion,
            bool ignoreSsl = false)
        {
            return GetConnection(new PasswordAuthenticator(
                networkAddress,
                provider,
                username,
                password,
                apiVersion,
                ignoreSsl,
                null));
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
        public static ISafeguardConnection Connect(
            string networkAddress,
            string provider,
            string username,
            SecureString password,
            RemoteCertificateValidationCallback validationCallback,
            int apiVersion = DefaultApiVersion)
        {
            return GetConnection(new PasswordAuthenticator(
                networkAddress,
                provider,
                username,
                password,
                apiVersion,
                false,
                validationCallback));
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
        public static ISafeguardConnection Connect(
            string networkAddress,
            string certificateThumbprint,
            int apiVersion = DefaultApiVersion,
            bool ignoreSsl = false)
        {
            return GetConnection(new CertificateAuthenticator(
                networkAddress,
                certificateThumbprint,
                apiVersion,
                ignoreSsl,
                null));
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
        public static ISafeguardConnection Connect(
            string networkAddress,
            string certificateThumbprint,
            RemoteCertificateValidationCallback validationCallback,
            int apiVersion = DefaultApiVersion)
        {
            return GetConnection(new CertificateAuthenticator(
                networkAddress,
                certificateThumbprint,
                apiVersion,
                false,
                validationCallback));
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
        public static ISafeguardConnection Connect(
            string networkAddress,
            string certificatePath,
            SecureString certificatePassword,
            int apiVersion = DefaultApiVersion,
            bool ignoreSsl = false)
        {
            return GetConnection(new CertificateAuthenticator(
                networkAddress,
                certificatePath,
                certificatePassword,
                apiVersion,
                ignoreSsl,
                null));
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
        public static ISafeguardConnection Connect(
            string networkAddress,
            string certificatePath,
            SecureString certificatePassword,
            RemoteCertificateValidationCallback validationCallback,
            int apiVersion = DefaultApiVersion)
        {
            return GetConnection(new CertificateAuthenticator(
                networkAddress,
                certificatePath,
                certificatePassword,
                apiVersion,
                false,
                validationCallback));
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
        public static ISafeguardConnection Connect(
            string networkAddress,
            IEnumerable<byte> certificateData,
            SecureString certificatePassword,
            int apiVersion = DefaultApiVersion,
            bool ignoreSsl = false)
        {
            return GetConnection(new CertificateAuthenticator(
                networkAddress,
                certificateData,
                certificatePassword,
                apiVersion,
                ignoreSsl,
                null));
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
        public static ISafeguardConnection Connect(
            string networkAddress,
            IEnumerable<byte> certificateData,
            SecureString certificatePassword,
            RemoteCertificateValidationCallback validationCallback,
            int apiVersion = DefaultApiVersion)
        {
            return GetConnection(new CertificateAuthenticator(
                networkAddress,
                certificateData,
                certificatePassword,
                apiVersion,
                false,
                validationCallback));
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
        public static ISafeguardConnection Connect(
            string networkAddress,
            string certificateThumbprint,
            string provider,
            int apiVersion = DefaultApiVersion,
            bool ignoreSsl = false)
        {
            return GetConnection(new CertificateAuthenticator(
                networkAddress,
                certificateThumbprint,
                apiVersion,
                ignoreSsl,
                null,
                provider));
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
        public static ISafeguardConnection Connect(
            string networkAddress,
            string certificateThumbprint,
            RemoteCertificateValidationCallback validationCallback,
            string provider,
            int apiVersion = DefaultApiVersion)
        {
            return GetConnection(new CertificateAuthenticator(
                networkAddress,
                certificateThumbprint,
                apiVersion,
                false,
                validationCallback,
                provider));
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
        public static ISafeguardConnection Connect(
            string networkAddress,
            string certificatePath,
            SecureString certificatePassword,
            string provider,
            int apiVersion = DefaultApiVersion,
            bool ignoreSsl = false)
        {
            return GetConnection(new CertificateAuthenticator(
                networkAddress,
                certificatePath,
                certificatePassword,
                apiVersion,
                ignoreSsl,
                null,
                provider));
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
        public static ISafeguardConnection Connect(
            string networkAddress,
            string certificatePath,
            SecureString certificatePassword,
            RemoteCertificateValidationCallback validationCallback,
            string provider,
            int apiVersion = DefaultApiVersion)
        {
            return GetConnection(new CertificateAuthenticator(
                networkAddress,
                certificatePath,
                certificatePassword,
                apiVersion,
                false,
                validationCallback,
                provider));
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
        public static ISafeguardConnection Connect(
            string networkAddress,
            IEnumerable<byte> certificateData,
            SecureString certificatePassword,
            string provider,
            int apiVersion = DefaultApiVersion,
            bool ignoreSsl = false)
        {
            return GetConnection(new CertificateAuthenticator(
                networkAddress,
                certificateData,
                certificatePassword,
                apiVersion,
                ignoreSsl,
                null,
                provider));
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
        public static ISafeguardConnection Connect(
            string networkAddress,
            IEnumerable<byte> certificateData,
            SecureString certificatePassword,
            RemoteCertificateValidationCallback validationCallback,
            string provider,
            int apiVersion = DefaultApiVersion)
        {
            return GetConnection(new CertificateAuthenticator(
                networkAddress,
                certificateData,
                certificatePassword,
                apiVersion,
                false,
                validationCallback,
                provider));
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
            public static ISafeguardEventListener GetPersistentEventListener(
                string networkAddress,
                string provider,
                string username,
                SecureString password,
                int apiVersion = DefaultApiVersion,
                bool ignoreSsl = false)
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
            public static ISafeguardEventListener GetPersistentEventListener(
                string networkAddress,
                string provider,
                string username,
                SecureString password,
                RemoteCertificateValidationCallback validationCallback,
                int apiVersion = DefaultApiVersion)
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
            public static ISafeguardEventListener GetPersistentEventListener(
                string networkAddress,
                string certificateThumbprint,
                int apiVersion = DefaultApiVersion,
                bool ignoreSsl = false)
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
            public static ISafeguardEventListener GetPersistentEventListener(
                string networkAddress,
                string certificateThumbprint,
                RemoteCertificateValidationCallback validationCallback,
                int apiVersion = DefaultApiVersion)
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
            public static ISafeguardEventListener GetPersistentEventListener(
                string networkAddress,
                IEnumerable<byte> certificateData,
                SecureString certificatePassword,
                int apiVersion = DefaultApiVersion,
                bool ignoreSsl = false)
            {
                return new PersistentSafeguardEventListener(GetConnection(new CertificateAuthenticator(
                    networkAddress,
                    certificateData,
                    certificatePassword,
                    apiVersion,
                    ignoreSsl,
                    null)));
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
            public static ISafeguardEventListener GetPersistentEventListener(
                string networkAddress,
                IEnumerable<byte> certificateData,
                SecureString certificatePassword,
                RemoteCertificateValidationCallback validationCallback,
                int apiVersion = DefaultApiVersion)
            {
                return new PersistentSafeguardEventListener(GetConnection(new CertificateAuthenticator(
                    networkAddress,
                    certificateData,
                    certificatePassword,
                    apiVersion,
                    false,
                    validationCallback)));
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
            public static ISafeguardEventListener GetPersistentEventListener(
                string networkAddress,
                string certificatePath,
                SecureString certificatePassword,
                int apiVersion = DefaultApiVersion,
                bool ignoreSsl = false)
            {
                return new PersistentSafeguardEventListener(GetConnection(new CertificateAuthenticator(
                    networkAddress,
                    certificatePath,
                    certificatePassword,
                    apiVersion,
                    ignoreSsl,
                    null)));
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
            public static ISafeguardEventListener GetPersistentEventListener(
                string networkAddress,
                string certificatePath,
                SecureString certificatePassword,
                RemoteCertificateValidationCallback validationCallback,
                int apiVersion = DefaultApiVersion)
            {
                return new PersistentSafeguardEventListener(GetConnection(new CertificateAuthenticator(
                    networkAddress,
                    certificatePath,
                    certificatePassword,
                    apiVersion,
                    false,
                    validationCallback)));
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
            public static ISafeguardEventListener GetPersistentEventListener(
                string networkAddress,
                string certificateThumbprint,
                string provider,
                int apiVersion = DefaultApiVersion,
                bool ignoreSsl = false)
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
            public static ISafeguardEventListener GetPersistentEventListener(
                string networkAddress,
                string certificateThumbprint,
                RemoteCertificateValidationCallback validationCallback,
                string provider,
                int apiVersion = DefaultApiVersion)
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
            public static ISafeguardEventListener GetPersistentEventListener(
                string networkAddress,
                IEnumerable<byte> certificateData,
                SecureString certificatePassword,
                string provider,
                int apiVersion = DefaultApiVersion,
                bool ignoreSsl = false)
            {
                return new PersistentSafeguardEventListener(GetConnection(new CertificateAuthenticator(
                    networkAddress,
                    certificateData,
                    certificatePassword,
                    apiVersion,
                    ignoreSsl,
                    null,
                    provider)));
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
            public static ISafeguardEventListener GetPersistentEventListener(
                string networkAddress,
                IEnumerable<byte> certificateData,
                SecureString certificatePassword,
                RemoteCertificateValidationCallback validationCallback,
                string provider,
                int apiVersion = DefaultApiVersion)
            {
                return new PersistentSafeguardEventListener(GetConnection(new CertificateAuthenticator(
                    networkAddress,
                    certificateData,
                    certificatePassword,
                    apiVersion,
                    false,
                    validationCallback,
                    provider)));
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
            public static ISafeguardEventListener GetPersistentEventListener(
                string networkAddress,
                string certificatePath,
                SecureString certificatePassword,
                string provider,
                int apiVersion = DefaultApiVersion,
                bool ignoreSsl = false)
            {
                return new PersistentSafeguardEventListener(GetConnection(new CertificateAuthenticator(
                    networkAddress,
                    certificatePath,
                    certificatePassword,
                    apiVersion,
                    ignoreSsl,
                    null,
                    provider)));
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
            public static ISafeguardEventListener GetPersistentEventListener(
                string networkAddress,
                string certificatePath,
                SecureString certificatePassword,
                RemoteCertificateValidationCallback validationCallback,
                string provider,
                int apiVersion = DefaultApiVersion)
            {
                return new PersistentSafeguardEventListener(GetConnection(new CertificateAuthenticator(
                    networkAddress,
                    certificatePath,
                    certificatePassword,
                    apiVersion,
                    false,
                    validationCallback,
                    provider)));
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
            public static ISafeguardA2AContext GetContext(
                string networkAddress,
                string certificateThumbprint,
                int apiVersion = DefaultApiVersion,
                bool ignoreSsl = false)
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
            public static ISafeguardA2AContext GetContext(
                string networkAddress,
                string certificateThumbprint,
                RemoteCertificateValidationCallback validationCallback,
                int apiVersion = DefaultApiVersion)
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
            public static ISafeguardA2AContext GetContext(
                string networkAddress,
                string certificatePath,
                SecureString certificatePassword,
                int apiVersion = DefaultApiVersion,
                bool ignoreSsl = false)
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
            public static ISafeguardA2AContext GetContext(
                string networkAddress,
                string certificatePath,
                SecureString certificatePassword,
                RemoteCertificateValidationCallback validationCallback,
                int apiVersion = DefaultApiVersion)
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
            public static ISafeguardA2AContext GetContext(
                string networkAddress,
                IEnumerable<byte> certificateData,
                SecureString certificatePassword,
                int apiVersion = DefaultApiVersion,
                bool ignoreSsl = false)
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
            public static ISafeguardA2AContext GetContext(
                string networkAddress,
                IEnumerable<byte> certificateData,
                SecureString certificatePassword,
                RemoteCertificateValidationCallback validationCallback,
                int apiVersion = DefaultApiVersion)
            {
                return new SafeguardA2AContext(networkAddress, certificateData, certificatePassword, apiVersion, false, validationCallback);
            }

            /// <summary>
            /// This static class provides access to Safeguard A2A Event functionality with persistent event listeners. Persistent
            /// event listeners can handle longer term service outages to reconnect SignalR even after it times out. It is
            /// recommended to use these interfaces when listening for Safeguard events from a long-running service.
            /// </summary>
            // ReSharper disable once MemberHidesStaticFromOuterClass
#pragma warning disable S3218 // Inner class intentionally shadows outer class member name for API consistency
            public static class Event
#pragma warning restore S3218
            {
                /// <summary>
                /// Get a persistent A2A event listener. The handler passed in will be registered
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
                public static ISafeguardEventListener GetPersistentA2AEventListener(
                    SecureString apiKey,
                    SafeguardEventHandler handler,
                    string networkAddress,
                    string certificateThumbprint,
                    int apiVersion = DefaultApiVersion,
                    bool ignoreSsl = false)
                {
                    return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, certificateThumbprint, apiVersion, ignoreSsl, null),
                        apiKey,
                        handler);
                }

                /// <summary>
                /// Get a persistent A2A event listener. The handler passed in will be registered
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
                public static ISafeguardEventListener GetPersistentA2AEventListener(
                    SecureString apiKey,
                    SafeguardEventHandler handler,
                    string networkAddress,
                    string certificateThumbprint,
                    RemoteCertificateValidationCallback validationCallback,
                    int apiVersion = DefaultApiVersion)
                {
                    return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, certificateThumbprint, apiVersion, false, validationCallback),
                        apiKey,
                        handler);
                }

                /// <summary>
                /// Get a persistent A2A event listener. The handler passed in will be registered
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
                public static ISafeguardEventListener GetPersistentA2AEventListener(
                    IEnumerable<SecureString> apiKeys,
                    SafeguardEventHandler handler,
                    string networkAddress,
                    string certificateThumbprint,
                    int apiVersion = DefaultApiVersion,
                    bool ignoreSsl = false)
                {
                    return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, certificateThumbprint, apiVersion, ignoreSsl, null),
                        apiKeys,
                        handler);
                }

                /// <summary>
                /// Get a persistent A2A event listener. The handler passed in will be registered
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
                public static ISafeguardEventListener GetPersistentA2AEventListener(
                    IEnumerable<SecureString> apiKeys,
                    SafeguardEventHandler handler,
                    string networkAddress,
                    string certificateThumbprint,
                    RemoteCertificateValidationCallback validationCallback,
                    int apiVersion = DefaultApiVersion)
                {
                    return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, certificateThumbprint, apiVersion, false, validationCallback),
                        apiKeys,
                        handler);
                }

                /// <summary>
                /// Get a persistent A2A event listener. The handler passed in will be registered
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
                public static ISafeguardEventListener GetPersistentA2AEventListener(
                    SecureString apiKey,
                    SafeguardEventHandler handler,
                    string networkAddress,
                    string certificatePath,
                    SecureString certificatePassword,
                    int apiVersion = DefaultApiVersion,
                    bool ignoreSsl = false)
                {
                    return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, certificatePath, certificatePassword, apiVersion, ignoreSsl, null),
                        apiKey,
                        handler);
                }

                /// <summary>
                /// Get a persistent A2A event listener. The handler passed in will be registered
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
                public static ISafeguardEventListener GetPersistentA2AEventListener(
                    SecureString apiKey,
                    SafeguardEventHandler handler,
                    string networkAddress,
                    string certificatePath,
                    SecureString certificatePassword,
                    RemoteCertificateValidationCallback validationCallback,
                    int apiVersion = DefaultApiVersion)
                {
                    return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(
                            networkAddress,
                            certificatePath,
                            certificatePassword,
                            apiVersion,
                            false,
                            validationCallback),
                        apiKey,
                        handler);
                }

                /// <summary>
                /// Get a persistent A2A event listener. The handler passed in will be registered
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
                public static ISafeguardEventListener GetPersistentA2AEventListener(
                    IEnumerable<SecureString> apiKeys,
                    SafeguardEventHandler handler,
                    string networkAddress,
                    string certificatePath,
                    SecureString certificatePassword,
                    int apiVersion = DefaultApiVersion,
                    bool ignoreSsl = false)
                {
                    return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, certificatePath, certificatePassword, apiVersion, ignoreSsl, null),
                        apiKeys,
                        handler);
                }

                /// <summary>
                /// Get a persistent A2A event listener. The handler passed in will be registered
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
                public static ISafeguardEventListener GetPersistentA2AEventListener(
                    IEnumerable<SecureString> apiKeys,
                    SafeguardEventHandler handler,
                    string networkAddress,
                    string certificatePath,
                    SecureString certificatePassword,
                    RemoteCertificateValidationCallback validationCallback,
                    int apiVersion = DefaultApiVersion)
                {
                    return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(
                            networkAddress,
                            certificatePath,
                            certificatePassword,
                            apiVersion,
                            false,
                            validationCallback),
                        apiKeys,
                        handler);
                }

                /// <summary>
                /// Get a persistent A2A event listener. The handler passed in will be registered
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
                public static ISafeguardEventListener GetPersistentA2AEventListener(
                    SecureString apiKey,
                    SafeguardEventHandler handler,
                    string networkAddress,
                    IEnumerable<byte> certificateData,
                    SecureString certificatePassword,
                    int apiVersion = DefaultApiVersion,
                    bool ignoreSsl = false)
                {
                    return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, certificateData, certificatePassword, apiVersion, ignoreSsl, null),
                        apiKey,
                        handler);
                }

                /// <summary>
                /// Get a persistent A2A event listener. The handler passed in will be registered
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
                public static ISafeguardEventListener GetPersistentA2AEventListener(
                    SecureString apiKey,
                    SafeguardEventHandler handler,
                    string networkAddress,
                    IEnumerable<byte> certificateData,
                    SecureString certificatePassword,
                    RemoteCertificateValidationCallback validationCallback,
                    int apiVersion = DefaultApiVersion)
                {
                    return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(
                            networkAddress,
                            certificateData,
                            certificatePassword,
                            apiVersion,
                            false,
                            validationCallback),
                        apiKey,
                        handler);
                }

                /// <summary>
                /// Get a persistent A2A event listener. The handler passed in will be registered
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
                public static ISafeguardEventListener GetPersistentA2AEventListener(
                    IEnumerable<SecureString> apiKeys,
                    SafeguardEventHandler handler,
                    string networkAddress,
                    IEnumerable<byte> certificateData,
                    SecureString certificatePassword,
                    int apiVersion = DefaultApiVersion,
                    bool ignoreSsl = false)
                {
                    return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(networkAddress, certificateData, certificatePassword, apiVersion, ignoreSsl, null),
                        apiKeys,
                        handler);
                }

                /// <summary>
                /// Get a persistent A2A event listener. The handler passed in will be registered
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
                public static ISafeguardEventListener GetPersistentA2AEventListener(
                    IEnumerable<SecureString> apiKeys,
                    SafeguardEventHandler handler,
                    string networkAddress,
                    IEnumerable<byte> certificateData,
                    SecureString certificatePassword,
                    RemoteCertificateValidationCallback validationCallback,
                    int apiVersion = DefaultApiVersion)
                {
                    return new PersistentSafeguardA2AEventListener(
                        new SafeguardA2AContext(
                            networkAddress,
                            certificateData,
                            certificatePassword,
                            apiVersion,
                            false,
                            validationCallback),
                        apiKeys,
                        handler);
                }
            }
        }

        /// <summary>
        /// This static class provides common authentication functionality for OAuth2/PKCE-based login methods.
        /// This class contains shared code for browser-based and non-interactive authentication flows.
        /// </summary>
        public static class AgentBasedLoginUtils
        {
            /// <summary>
            /// Standard redirect URI for installed applications
            /// </summary>
            public const string RedirectUri = "urn:InstalledApplication";

            /// <summary>
            /// Redirect URI for TCP listener-based authentication
            /// </summary>
            public const string RedirectUriTcpListener = "urn:InstalledApplicationTcpListener";

            private static readonly HttpClient Http = CreateHttpClient();

            /// <summary>
            /// Posts the OAuth2 authorization code to complete the PKCE authentication flow and obtain an RSTS access token.
            /// </summary>
            /// <param name="appliance">Network address of the Safeguard appliance.</param>
            /// <param name="authorizationCode">The authorization code received from the authorization endpoint.</param>
            /// <param name="codeVerifier">The PKCE code verifier that matches the code challenge sent in the authorization request.</param>
            /// <param name="redirectUri">The redirect URI that was used in the authorization request.</param>
            /// <param name="httpClient">Optional HttpClient instance to use for the request. If null, a default client will be used.</param>
            /// <returns>An RSTS access token as a SecureString.</returns>
            public static SecureString PostAuthorizationCodeFlow(string appliance, string authorizationCode, string codeVerifier, string redirectUri)
            {
                var safeguardRstsUrl = $"https://{appliance}/RSTS";
                var data = JsonConvert.SerializeObject(new
                {
                    grant_type = "authorization_code",
                    redirect_uri = redirectUri,
                    code = authorizationCode,
                    code_verifier = codeVerifier,
                });

                var json = ApiRequest(HttpMethod.Post, $"{safeguardRstsUrl}/oauth2/token", data);

                var jObject = JObject.Parse(json);
                return jObject.GetValue("access_token")?.ToString().ToSecureString();
            }

            /// <summary>
            /// Posts the RSTS access token to the Safeguard API to obtain a Safeguard user access token.
            /// </summary>
            /// <param name="appliance">Network address of the Safeguard appliance.</param>
            /// <param name="rstsAccessToken">The RSTS access token obtained from the OAuth2 flow.</param>
            /// <param name="apiVersion">Target API version to use.</param>
            /// <param name="httpClient">Optional HttpClient instance to use for the request. If null, a default client will be used.</param>
            /// <returns>A JObject containing the login response with the Safeguard user token.</returns>
            public static JObject PostLoginResponse(string appliance, SecureString rstsAccessToken, int apiVersion = DefaultApiVersion)
            {
                var safeguardCoreUrl = $"https://{appliance}/service/core/v{apiVersion}";
                var data = JsonConvert.SerializeObject(new
                {
                    StsAccessToken = rstsAccessToken.ToInsecureString(),
                });

                var json = ApiRequest(HttpMethod.Post, $"{safeguardCoreUrl}/Token/LoginResponse", data);

                return JObject.Parse(json);
            }

            /// <summary>
            /// Generates a cryptographically random code verifier for PKCE (Proof Key for Code Exchange) OAuth2 flow.
            /// The code verifier is a high-entropy cryptographic random string used to securely verify the authorization code exchange.
            /// </summary>
            /// <returns>A base64url-encoded code verifier string.</returns>
            public static string OAuthCodeVerifier()
            {
                var bytes = new byte[60];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(bytes);
                }

                return ToBase64Url(bytes);
            }

            /// <summary>
            /// Generates an OAuth2 PKCE code challenge from a code verifier using SHA256 hashing.
            /// The code challenge is derived from the code verifier and sent in the authorization request.
            /// </summary>
            /// <param name="codeVerifier">The code verifier string from which to generate the challenge.</param>
            /// <returns>A base64url-encoded SHA256 hash of the code verifier.</returns>
            public static string OAuthCodeChallenge(string codeVerifier)
            {
                using (var sha = SHA256.Create())
                {
                    var hash = sha.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier));

                    return ToBase64Url(hash);
                }
            }

            /// <summary>
            /// Generates a cryptographically random CSRF (Cross-Site Request Forgery) token for state validation.
            /// This token should be used to prevent CSRF attacks in OAuth2 flows by validating that authorization
            /// responses match the original request.
            /// </summary>
            /// <returns>A base64url-encoded random token string.</returns>
            public static string GenerateCsrfToken()
            {
                byte[] bytes = new byte[32];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(bytes);
                }

                return ToBase64Url(bytes);
            }

            private static string ApiRequest(HttpMethod method, string url, string postData)
            {
                var req = new HttpRequestMessage
                {
                    Method = method,
                    RequestUri = new Uri(url, UriKind.Absolute),
                };

                req.Headers.Add("Accept", "application/json");
                req.Content = new StringContent(postData, Encoding.UTF8, "application/json");

                try
                {
                    var res = Http.SendAsync(req).GetAwaiter().GetResult();
                    var msg = res.Content?.ReadAsStringAsync().GetAwaiter().GetResult();

                    if (!res.IsSuccessStatusCode)
                    {
                        throw new SafeguardDotNetException($"Error returned from Safeguard API, Error: {res.StatusCode} {msg}", res.StatusCode, msg);
                    }

                    return msg;
                }
                catch (TaskCanceledException)
                {
                    throw new SafeguardDotNetException($"Request timeout to {url}.");
                }
            }

            private static HttpClient CreateHttpClient()
            {
                var handler = new HttpClientHandler()
                {
                    SslProtocols = System.Security.Authentication.SslProtocols.Tls12,
#pragma warning disable S4830 // Server certificate validation is intentionally bypassed for RSTS token requests
                    ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true,
#pragma warning restore S4830
                };

                return new HttpClient(handler);
            }

            private static string ToBase64Url(byte[] data)
            {
                return Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            }
        }

        private static SafeguardConnection GetConnection(IAuthenticationMechanism authenticationMechanism)
        {
            authenticationMechanism.RefreshAccessToken();
            return new SafeguardConnection(authenticationMechanism);
        }
    }
}
