// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.Event
{
    using System;

    using OneIdentity.SafeguardDotNet.A2A;

    /// <summary>
    /// A callback that will be called when a given event occurs in Safeguard. The callback will
    /// receive the event name and JSON data representing the event.
    /// </summary>
    /// <param name="eventName">Name of the event.</param>
    /// <param name="eventBody">JSON string containing event data.</param>
    public delegate void SafeguardEventHandler(string eventName, string eventBody);

    /// <summary>
    /// A callback that will be called whenever the event listener connection state Changes.
    /// </summary>
    /// <param name="eventListenerState">New connection state of the event listener.</param>
    public delegate void SafeguardEventListenerStateCallback(SafeguardEventListenerState eventListenerState);

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
        /// Set an event listener callback that will be called each time the connection
        /// state changes of the event listener.
        /// </summary>
        /// <param name="eventListenerStateCallback">Callback method.</param>
        void SetEventListenerStateCallback(SafeguardEventListenerStateCallback eventListenerStateCallback);

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
