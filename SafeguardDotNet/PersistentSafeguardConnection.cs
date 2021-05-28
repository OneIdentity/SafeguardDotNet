using OneIdentity.SafeguardDotNet.Event;
using System;
using System.Collections.Generic;
using System.Text;

namespace OneIdentity.SafeguardDotNet
{
    class PersistentSafeguardConnection : ISafeguardConnection
    {
        private ISafeguardConnection _connection;

        public PersistentSafeguardConnection(ISafeguardConnection connection) => _connection = connection;


        public IStreamingRequest Streaming => _connection.Streaming;

        public void Dispose() => _connection.Dispose();

        public int GetAccessTokenLifetimeRemaining() => _connection.GetAccessTokenLifetimeRemaining();

        public ISafeguardEventListener GetEventListener() => _connection.GetEventListener();

        public ISafeguardEventListener GetPersistentEventListener() => _connection.GetPersistentEventListener();

        public string InvokeMethod(Service service, Method method, string relativeUrl, string body = null, IDictionary<string, string> parameters = null, IDictionary<string, string> additionalHeaders = null, TimeSpan? timeout = null)
        {
            if(_connection.GetAccessTokenLifetimeRemaining() <= 0)
                _connection.RefreshAccessToken();
            return _connection.InvokeMethod(service, method, relativeUrl, body, parameters, additionalHeaders, timeout);

        }

        public string InvokeMethodCsv(Service service, Method method, string relativeUrl, string body = null, IDictionary<string, string> parameters = null, IDictionary<string, string> additionalHeaders = null, TimeSpan? timeout = null)
        {
            if (_connection.GetAccessTokenLifetimeRemaining() <= 0)
                _connection.RefreshAccessToken();
            return _connection.InvokeMethodCsv(service, method, relativeUrl, body, parameters, additionalHeaders, timeout);
        }

        public FullResponse InvokeMethodFull(Service service, Method method, string relativeUrl, string body = null, IDictionary<string, string> parameters = null, IDictionary<string, string> additionalHeaders = null, TimeSpan? timeout = null)
        {
            if (_connection.GetAccessTokenLifetimeRemaining() <= 0)
                _connection.RefreshAccessToken();
            return _connection.InvokeMethodFull(service, method, relativeUrl, body, parameters, additionalHeaders, timeout);
        }

        public FullResponse JoinSPS(ISafeguardSessionsConnection SpsConnection, string CertificateChain, string SppAddress)
        {
            if (_connection.GetAccessTokenLifetimeRemaining() <= 0)
                _connection.RefreshAccessToken();
            return _connection.JoinSPS(SpsConnection, CertificateChain, SppAddress);
        }

        public void LogOut() => _connection.LogOut();

        public void RefreshAccessToken() => _connection.RefreshAccessToken();
    }
}
