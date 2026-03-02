// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.Event
{
    public class SafeguardEventListenerDisconnectedException : SafeguardDotNetException
    {
        public SafeguardEventListenerDisconnectedException()
            : base("SafeguardEventListener has permanently disconnected SignalR connection")
        {
        }
    }
}
