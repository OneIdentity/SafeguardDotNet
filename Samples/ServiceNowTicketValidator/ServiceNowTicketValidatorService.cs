using System.Configuration;
using System.Security;
using OneIdentity.SafeguardDotNet;
using OneIdentity.SafeguardDotNet.Event;

namespace ServiceNowTicketValidator
{
    internal class ServiceNowTicketValidatorService
    {
        private readonly string _safeguardAddress;
        private readonly string _safeguardClientCertificateThumbprint;
        private readonly int _safeguardApiVersion;
        private readonly bool _safeguardIgnoreSsl;

        private readonly string _serviceNowDnsName;
        private readonly SecureString _serviceNowClientSecret;
        private readonly string _serviceNowUserName;
        private readonly SecureString _safeguardA2AApiKeyForServiceNowPassword;

        private SecureString _serviceNowPassword;
        private ISafeguardEventListener _eventListener;
        private ISafeguardConnection _connection;
        private ServiceNowTicketValidator _validator;

        public ServiceNowTicketValidatorService()
        {
            _safeguardAddress =
                ConfigUtils.ReadRequiredSettingFromAppConfig("SafeguardAddress", "Safeguard appliance network address");
            _safeguardClientCertificateThumbprint =
                ConfigUtils.ReadRequiredSettingFromAppConfig("SafeguardClientCertificateThumbprint",
                    "Safeguard client certificate thumbprint");
            _safeguardApiVersion =
                int.Parse(ConfigUtils.ReadRequiredSettingFromAppConfig("SafeguardApiVersion", "Safeguard API version"));
            _safeguardIgnoreSsl = bool.Parse(ConfigurationManager.AppSettings["SafeguardIgnoreSsl"]);
            _serviceNowDnsName =
                ConfigUtils.ReadRequiredSettingFromAppConfig("ServiceNowDnsName", "ServiceNow server DNS name");
            _serviceNowClientSecret = ConfigUtils.ReadSettingFromAppConfigIfPresent("ServiceNowClientSecret")
                ?.ToSecureString();
            _serviceNowUserName =
                ConfigUtils.ReadRequiredSettingFromAppConfig("ServiceNowUserName", "ServiceNow user name");
            _safeguardA2AApiKeyForServiceNowPassword = ConfigUtils
                .ReadRequiredSettingFromAppConfig("SafeguardA2AApiKeyForServiceNowPassword",
                    "Safeguard A2A API key for retrieving ServiceNow password").ToSecureString();
        }

        private void HandlePendingApprovalNotification(string eventName, string eventBody)
        {
            // TODO: check to be sure it has a ticket number (assume ServiceNow / check for INC)

            var ticketNumber = "";

            // TODO: bail early if no ticket number

            // TODO: get relevant info for approve or deny

            var accessRequestId = "";

            if (_connection.GetAccessTokenLifetimeRemaining() == 0)
                _connection.RefreshAccessToken();

            if (_validator.CheckTicket(ticketNumber))
                _connection.InvokeMethod(Service.Core, Method.Post, $"AccessRequests/{accessRequestId}/Approve");
            else
                _connection.InvokeMethod(Service.Core, Method.Post, $"AccessRequests/{accessRequestId}/Deny");
        }

        public void Start()
        {
            _eventListener = Safeguard.Event.GetPersistentEventListener(_safeguardAddress,
                _safeguardClientCertificateThumbprint, _safeguardApiVersion, _safeguardIgnoreSsl);
            _connection = Safeguard.Connect(_safeguardAddress, _safeguardClientCertificateThumbprint,
                _safeguardApiVersion, _safeguardIgnoreSsl);
            using (var a2AContext = Safeguard.A2A.GetContext(_safeguardAddress, _safeguardClientCertificateThumbprint,
                _safeguardApiVersion, _safeguardIgnoreSsl))
            {
                _serviceNowPassword = a2AContext.RetrievePassword(_safeguardA2AApiKeyForServiceNowPassword);
            }

            _validator = new ServiceNowTicketValidator(_serviceNowDnsName, _serviceNowClientSecret, _serviceNowUserName,
                _serviceNowPassword);
            _eventListener.RegisterEventHandler("AccessRequestPendingApproval", HandlePendingApprovalNotification);

            _eventListener.Start();
        }

        public void Stop()
        {
            _eventListener.Stop();

            _eventListener?.Dispose();
            _connection?.Dispose();
            _serviceNowPassword?.Dispose();
            _validator?.Dispose();
            _eventListener = null;
            _connection = null;
            _serviceNowPassword = null;
            _validator = null;
        }
    }
}
