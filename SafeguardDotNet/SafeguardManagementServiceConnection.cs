// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet
{
    using System;

    using OneIdentity.SafeguardDotNet.Authentication;
    using OneIdentity.SafeguardDotNet.Event;
    using OneIdentity.SafeguardDotNet.Sps;

    internal class SafeguardManagementServiceConnection : SafeguardConnection
    {
        private readonly Uri _managementUrl;

        internal SafeguardManagementServiceConnection(IAuthenticationMechanism parentAuthenticationMechanism, string networkAddress)
            : base(new ManagementServiceAuthenticator(parentAuthenticationMechanism, networkAddress))
        {
            _managementUrl = new Uri($"https://{authenticationMechanism.NetworkAddress}/service/management/v{authenticationMechanism.ApiVersion}/", UriKind.Absolute);
        }

        public override FullResponse JoinSps(ISafeguardSessionsConnection spsConnection, string certificateChain, string sppAddress)
        {
            throw new SafeguardDotNetException("Management connection cannot be used to join SPS.");
        }

        public override ISafeguardEventListener GetEventListener()
        {
            throw new SafeguardDotNetException("Management connection does not support event listeners.");
        }

        public override ISafeguardEventListener GetPersistentEventListener()
        {
            throw new SafeguardDotNetException("Management connection does not support event listeners.");
        }

        protected override Uri GetClientForService(Service service)
        {
            if (service == Service.Management)
            {
                return _managementUrl;
            }

            throw new SafeguardDotNetException($"{service} service cannot be invoked with a management connection.");
        }
    }
}
