using System.Collections.Generic;
using Newtonsoft.Json.Linq;

namespace OneIdentity.SafeguardDotNet
{
    public enum Service
    {
        Core,
        Appliance,
        Notification,
        A2A
    };

    public enum Method
    {
        Post,
        Get,
        Put,
        Delete
    }

    public interface ISafeguardConnection
    {
        int GetAccessTokenLifetimeRemaining();

        void RefreshAccessToken();

        JToken InvokeMethod(Service service, Method method, string relativeUrl,
            JToken body, IDictionary<string, string> parameters, IDictionary<string, string> additionalHeaders);
    }
}
