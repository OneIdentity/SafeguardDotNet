using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Security;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace OneIdentity.SafeguardDotNet.Authentication
{
    internal abstract class AuthenticatorBase : IAuthenticationMechanism
    {
        private bool _disposed;

        protected SecureString AccessToken;

        protected readonly string SafeguardCoreUrl;

        private readonly HttpClient _http;

        protected readonly CertificateContext ClientCertificate;

        protected AuthenticatorBase(string networkAddress, int apiVersion, bool ignoreSsl, RemoteCertificateValidationCallback validationCallback, CertificateContext clientCertificate = null)
        {
            NetworkAddress = networkAddress;
            ApiVersion = apiVersion;
            IgnoreSsl = ignoreSsl;
            ValidationCallback = validationCallback;
            ClientCertificate = clientCertificate;

            SafeguardCoreUrl = $"https://{NetworkAddress}/service/core/v{ApiVersion}";

            _http = CreateHttpClient();
        }

        public abstract string Id { get; }

        public string NetworkAddress { get; }

        public int ApiVersion { get; }

        public bool IgnoreSsl { get; }

        public RemoteCertificateValidationCallback ValidationCallback { get; }

        public virtual bool IsAnonymous => false;

        protected bool IsDisposed => _disposed;

        public bool HasAccessToken()
        {
            return AccessToken != null;
        }

        public void ClearAccessToken()
        {
            AccessToken?.Dispose();
            AccessToken = null;
        }

        public SecureString GetAccessToken()
        {
            if (_disposed)
                throw new ObjectDisposedException("AuthenticatorBase");
            return AccessToken;
        }

        public int GetAccessTokenLifetimeRemaining()
        {
            if (_disposed)
                throw new ObjectDisposedException("AuthenticatorBase");
            if (!HasAccessToken())
                return 0;

            var ttl = ApiRequest(HttpMethod.Get, $"{SafeguardCoreUrl}/LoginMessage", null, AccessToken.ToInsecureString(), true);

            if (ttl == null || !int.TryParse(ttl, out var remaining))
                return 10; // Random magic value... the access token was good, but for some reason it didn't return the remaining lifetime
            return remaining;
        }

        public void RefreshAccessToken()
        {
            if (_disposed)
                throw new ObjectDisposedException("AuthenticatorBase");
            using (var rStsToken = GetRstsTokenInternal())
            {
                var data = JsonConvert.SerializeObject(new
                {
                    StsAccessToken = rStsToken.ToInsecureString()
                });

                var json = ApiRequest(HttpMethod.Post, $"{SafeguardCoreUrl}/Token/LoginResponse", data);

                var jObject = JObject.Parse(json);
                AccessToken = jObject.GetValue("UserToken")?.ToString().ToSecureString();
            }
        }

        public string ResolveProviderToScope(string provider)
        {
            try
            {
                var json = ApiRequest(HttpMethod.Get, $"{SafeguardCoreUrl}/AuthenticationProviders");

                var jProviders = JArray.Parse(json);
                var knownScopes = new List<(string RstsProviderId, string Name, string RstsProviderScope)>();
                if (jProviders != null)
                    knownScopes = jProviders.Select(s => (Id: s["RstsProviderId"].ToString(), Name: s["Name"].ToString(), Scope: s["RstsProviderScope"].ToString())).ToList();

                // 3 step check for determining if the user provided scope is valid:
                //
                // 1. User value == RSTSProviderId
                // 2. User value == Identity Provider Name.
                //    - This allows the caller to specify the domain name for AD.
                // 3. User Value is contained in RSTSProviderId.
                //    - This allows the caller to specify the provider Id rather than the full RSTSProviderId.
                //    - Such a broad check could provide some issues with false matching, however since this
                //      was in the original code, this check has been left in place.
                var scope = knownScopes.FirstOrDefault(s => s.RstsProviderId.EqualsNoCase(provider));
                if (scope.RstsProviderId == null)
                {
                    scope = knownScopes.FirstOrDefault(s => s.Name.EqualsNoCase(provider));

                    if (scope.Name == null)
                    {
                        scope = knownScopes.FirstOrDefault(s => s.RstsProviderId.ContainsNoCase(provider));

                        if (scope.RstsProviderId == null)
                        {
                            throw new SafeguardDotNetException(
                            $"Unable to find scope matching '{provider}' in [{string.Join(",", knownScopes)}]");
                        }
                    }

                }

                return scope.RstsProviderScope;
            }
            catch (SafeguardDotNetException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new SafeguardDotNetException("Unable to connect to determine identity provider", ex);
            }
        }

        protected abstract SecureString GetRstsTokenInternal();

        protected HttpClient CreateHttpClient()
        {
            var handler = new HttpClientHandler();

            handler.SslProtocols = System.Security.Authentication.SslProtocols.Tls12;

            if (ClientCertificate?.Certificate != null)
            {
                handler.ClientCertificateOptions = ClientCertificateOption.Manual;
                handler.ClientCertificates.Add(ClientCertificate.Certificate);
            }

            if (IgnoreSsl)
            {
                handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;
            }
            else if (ValidationCallback != null)
            {
                handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => ValidationCallback(message, cert, chain, errors);
            }

            return new HttpClient(handler);
        }

        protected string ApiRequest(HttpMethod method, string url, string postData = null, string authToken = null, bool getTtl = false)
        {
            var req = new HttpRequestMessage
            {
                Method = method,
                RequestUri = new Uri(url, UriKind.Absolute),
            };

            req.Headers.Add("Accept", "application/json");

            if (authToken != null)
            {
                req.Headers.Add("Authorization", $"Bearer {authToken}");
            }

            if (postData != null)
            {
                req.Content = new StringContent(postData, Encoding.UTF8, "application/json");
            }

            try
            {
                var res = _http.SendAsync(req).GetAwaiter().GetResult();
                var msg = res.Content?.ReadAsStringAsync().GetAwaiter().GetResult();

                if (getTtl)
                {
                    if (res.Headers.TryGetValues("X-TokenLifetimeRemaining", out var ttl))
                    {
                        return ttl.FirstOrDefault();
                    }

                    return "0";
                }

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

        public abstract object Clone();

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    ClearAccessToken();
                }

                _disposed = true;
            }
        }
    }
}
