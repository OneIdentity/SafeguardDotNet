using System;
using System.Threading.Tasks;

namespace OneIdentity.SafeguardDotNet.GuiLogin
{
    public static class LoginWindow
    {
        private static string ShowRstsWindow(string appliance, string primaryProviderId = "", string secondaryProviderId = "")
        {
            var rstsWindow = new RstsWindow(appliance);
            if (!rstsWindow.Show(primaryProviderId, secondaryProviderId))
            {
                throw new Exception("Unable to correctly manipulate browser");
            }
            if (string.IsNullOrEmpty(rstsWindow.AuthorizationCode))
            {
                throw new Exception("Unable to obtain authorization code");
            }
            return rstsWindow.AuthorizationCode;
        }

        public static Task<ISafeguardConnection> Connect(string appliance)
        {
            return Task.Run(() =>
            {
                var authorizationCode = ShowRstsWindow(appliance);
                


                var accessToken = "??replaceme??".ToSecureString();
                return Safeguard.Connect(appliance, accessToken);
            });
        }
    }
}
