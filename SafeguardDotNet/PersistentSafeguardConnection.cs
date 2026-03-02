// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet
{
    using System;
    using System.Collections.Generic;
    using System.Security;

    using OneIdentity.SafeguardDotNet.Event;
    using OneIdentity.SafeguardDotNet.Sps;

    internal class PersistentSafeguardConnection : ISafeguardConnection
    {
        private readonly ISafeguardConnection _connection;

        public PersistentSafeguardConnection(ISafeguardConnection connection) => _connection = connection;

        public IStreamingRequest Streaming => _connection.Streaming;

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                _connection.Dispose();
            }
        }

        public int GetAccessTokenLifetimeRemaining() => _connection.GetAccessTokenLifetimeRemaining();

        public ISafeguardEventListener GetEventListener() => _connection.GetEventListener();

        public SecureString GetAccessToken() => _connection.GetAccessToken();

        public ISafeguardConnection GetManagementServiceConnection(string networkAddress)
        {
            return _connection.GetManagementServiceConnection(networkAddress);
        }

        public ISafeguardEventListener GetPersistentEventListener() => _connection.GetPersistentEventListener();

        public string InvokeMethod(Service service, Method method, string relativeUrl, string body = null, IDictionary<string, string> parameters = null, IDictionary<string, string> additionalHeaders = null, TimeSpan? timeout = null)
        {
            if (_connection.GetAccessTokenLifetimeRemaining() <= 0)
            {
                _connection.RefreshAccessToken();
            }

            return _connection.InvokeMethod(service, method, relativeUrl, body, parameters, additionalHeaders, timeout);
        }

        public string InvokeMethodCsv(Service service, Method method, string relativeUrl, string body = null, IDictionary<string, string> parameters = null, IDictionary<string, string> additionalHeaders = null, TimeSpan? timeout = null)
        {
            if (_connection.GetAccessTokenLifetimeRemaining() <= 0)
            {
                _connection.RefreshAccessToken();
            }

            return _connection.InvokeMethodCsv(service, method, relativeUrl, body, parameters, additionalHeaders, timeout);
        }

        public FullResponse InvokeMethodFull(Service service, Method method, string relativeUrl, string body = null, IDictionary<string, string> parameters = null, IDictionary<string, string> additionalHeaders = null, TimeSpan? timeout = null)
        {
            if (_connection.GetAccessTokenLifetimeRemaining() <= 0)
            {
                _connection.RefreshAccessToken();
            }

            return _connection.InvokeMethodFull(service, method, relativeUrl, body, parameters, additionalHeaders, timeout);
        }

        public FullResponse JoinSps(ISafeguardSessionsConnection spsConnection, string certificateChain, string sppAddress)
        {
            if (_connection.GetAccessTokenLifetimeRemaining() <= 0)
            {
                _connection.RefreshAccessToken();
            }

            return _connection.JoinSps(spsConnection, certificateChain, sppAddress);
        }

        public void LogOut() => _connection.LogOut();

        public void RefreshAccessToken() => _connection.RefreshAccessToken();
    }
}
