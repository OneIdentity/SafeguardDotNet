using System.Collections.Generic;
using Newtonsoft.Json.Linq;

namespace OneIdentity.SafeguardDotNet
{
    public interface ISafeguardConnection
    {
        int GetAccessTokenLifetimeRemaining();

        void RefreshAccessToken();

        string InvokeMethod(Service service, Method method, string relativeUrl,
            string body = null, IDictionary<string, string> parameters = null,
            IDictionary<string, string> additionalHeaders = null);

        JToken InvokeMethodParsed(Service service, Method method, string relativeUrl,
            JToken body = null, IDictionary<string, string> parameters = null,
            IDictionary<string, string> additionalHeaders = null);

        FullResponse InvokeMethodFull(Service service, Method method, string relativeUrl,
            string body = null, IDictionary<string, string> parameters = null,
            IDictionary<string, string> additionalHeaders = null);
    }
}
