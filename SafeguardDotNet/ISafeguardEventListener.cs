using System;

namespace OneIdentity.SafeguardDotNet
{
    public delegate void SafeguardEventHandler(string eventName, string eventBody);

    public interface ISafeguardEventListener : IDisposable
    {
        void RegisterEventHandler(string eventName, SafeguardEventHandler handler);

        void Start();

        void Stop();
    }
}
