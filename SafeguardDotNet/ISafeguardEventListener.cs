using System;
using Newtonsoft.Json.Linq;

namespace OneIdentity.SafeguardDotNet
{
    public delegate void SafeguardEventHandler(string eventName, string eventBody);

    public delegate void SafeguardParsedEventHandler(string eventName, JToken eventBody);

    public interface ISafeguardEventListener : IDisposable
    {
        void RegisterEventHandler(string eventName, SafeguardEventHandler handler);

        void RegisterEventHandler(string eventName, SafeguardParsedEventHandler handler);

        void Start();

        void Stop();
    }
}
