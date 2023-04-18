using System;
using System.Net.Security;
using System.Security;
using Newtonsoft.Json.Linq;
using RestSharp;

namespace OneIdentity.SafeguardDotNet.Authentication
{
    internal class PasswordAuthenticator : AuthenticatorBase
    {
        private bool _disposed;

        private readonly string _provider;
        private string _providerScope;
        private readonly string _username;
        private readonly SecureString _password;

        public PasswordAuthenticator(string networkAddress, string provider, string username, SecureString password, int apiVersion, 
            bool ignoreSsl, RemoteCertificateValidationCallback validationCallback) : base(networkAddress, apiVersion, ignoreSsl, validationCallback)
        {
            _provider = provider;
            if (string.IsNullOrEmpty(_provider))
                _providerScope = "rsts:sts:primaryproviderid:local";
            _username = username;
            if (password == null)
                throw new ArgumentException("Parameter may not be null", nameof(password));
            _password = password.Copy();
        }

        public override string Id => "Password";

        protected override SecureString GetRstsTokenInternal()
        {
            if (_disposed)
                throw new ObjectDisposedException("PasswordAuthenticator");
            if (_providerScope == null)
                _providerScope = ResolveProviderToScope(_provider);
            var request = new RestRequest("oauth2/token", RestSharp.Method.Post)
                .AddHeader("Accept", "application/json")
                .AddHeader("Content-type", "application/json")
                .AddJsonBody(new
                {
                    grant_type = "password",
                    username = _username,
                    // SecureString handling here basically negates the use of a secure string anyway, but when calling a Web API
                    // I'm not sure there is anything you can do about it.
                    password = _password.ToInsecureString(),
                    scope = _providerScope
                });
            var response = RstsClient.Execute(request);
            if (response.ResponseStatus != ResponseStatus.Completed && response.ResponseStatus != ResponseStatus.Error)
                throw new SafeguardDotNetException($"Unable to connect to RSTS service {RstsClient.Options.BaseUrl}, Error: " +
                                                   response.ErrorMessage);
            if (!response.IsSuccessful)
                throw new SafeguardDotNetException(
                    $"Error using password grant_type with scope {_providerScope}, Error: " +
                    $"{response.StatusCode} {response.Content}", response.StatusCode, response.Content);
            var jObject = JObject.Parse(response.Content);
            return jObject.GetValue("access_token")?.ToString().ToSecureString();
        }

        public override object Clone()
        {
            var auth =
                new PasswordAuthenticator(NetworkAddress, _provider, _username, _password, ApiVersion, IgnoreSsl, ValidationCallback)
                {
                    AccessToken = AccessToken?.Copy()
                };
            return auth;
        }

        protected override void Dispose(bool disposing)
        {
            if (_disposed || !disposing)
                return;
            base.Dispose(true);
            try
            {
                _password?.Dispose();
            }
            finally
            {
                _disposed = true;
            }
        }
    }
}
