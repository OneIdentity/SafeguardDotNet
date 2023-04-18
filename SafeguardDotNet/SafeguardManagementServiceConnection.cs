using OneIdentity.SafeguardDotNet.Authentication;
using OneIdentity.SafeguardDotNet.Event;
using OneIdentity.SafeguardDotNet.Sps;
using RestSharp;
using System;
using System.Collections.Generic;
using System.Text;

namespace OneIdentity.SafeguardDotNet
{
    internal class SafeguardManagementServiceConnection : SafeguardConnection
    {
        private readonly RestClient _managementClient;

        internal SafeguardManagementServiceConnection(IAuthenticationMechanism parentAuthenticationMechanism, string networkAddress)
            : base(new ManagementServiceAuthenticator(parentAuthenticationMechanism, networkAddress))
        {
            var safeguardManagementUrl = $"https://{_authenticationMechanism.NetworkAddress}/service/management/v{_authenticationMechanism.ApiVersion}";
            _managementClient = CreateRestClient(safeguardManagementUrl);
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

        protected override RestClient GetClientForService(Service service)
        {
            if (service == Service.Management)
                return _managementClient;
            throw new SafeguardDotNetException($"{service} service cannot be invoked with a management connection.");
        }
    }
}
