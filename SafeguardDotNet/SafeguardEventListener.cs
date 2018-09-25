using System;

namespace OneIdentity.SafeguardDotNet
{
    internal class SafeguardEventListener : ISafeguardEventListener
    {
        public SafeguardEventListener()
        {
        }

        public void Dispose()
        {
            throw new NotImplementedException();
        }

        public void RegisterEventHandler(string eventName, SafeguardEventHandler handler)
        {
            throw new NotImplementedException();
        }

        public void Start()
        {
            throw new NotImplementedException();
        }

        public void Stop()
        {
            throw new NotImplementedException();
        }
    }
}
