using System;

namespace OneIdentity.SafeguardDotNet.Event
{
    /// <summary>
    /// A callback that will be called when a given event occurs in Safeguard. The callback will
    /// receive the event name and JSON data representing the event.
    /// </summary>
    /// <param name="eventName">Name of the event.</param>
    /// <param name="eventBody">JSON string containing event data.</param>
    public delegate void SafeguardEventHandler(string eventName, string eventBody);

    /// <summary>
    /// This is an event listener interface that will allow you to be notified each time something
    /// changes on Safeguard. The events that you are notified for depend on the role and event
    /// registrations of the authenticated user. Safeguard event listeners use SignalR to make
    /// long-lived connections to Safeguard.
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
