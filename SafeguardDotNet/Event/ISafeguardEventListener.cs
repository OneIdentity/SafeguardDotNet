using System;

namespace OneIdentity.SafeguardDotNet.Event
{
    public delegate void SafeguardEventHandler(string eventName, string eventBody);

    /// <summary>
    /// This is an event listener interface that will allow you to be notified each time something
    /// changes on Safeguard. The events that you are notified for depend on the role and event
    /// registrations of the authenticated user.
    /// </summary>
    public interface ISafeguardEventListener : IDisposable
    {
        /// <summary>
        /// Register an event handler to be called each time the specified event occurs. Multiple
        /// handlers may be registered for each event.
        /// </summary>
        /// <param name="eventName">Name of the event.</param>
        /// <param name="handler">Callback method.</param>
        void RegisterEventHandler(string eventName, SafeguardEventHandler handler);

        /// <summary>
        /// Start listening for Safeguard events in a background thread.
        /// </summary>
        void Start();

        /// <summary>
        /// Stop listening for Safeguard events in a background thread.
        /// </summary>
        void Stop();
    }
}
