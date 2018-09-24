using System.Collections.Generic;
using System.Net;

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

    public class FullResponse
    {
        public HttpStatusCode StatusCode;
        public IDictionary<string, string> Headers;
        public string Body;
    }
}
