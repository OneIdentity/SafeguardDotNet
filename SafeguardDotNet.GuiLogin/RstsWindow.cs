using System;
using System.Text.RegularExpressions;
using System.Web;
using System.Windows.Forms;

namespace OneIdentity.SafeguardDotNet.GuiLogin
{
    internal class RstsWindow
    {
        private const string ClientId = "00000000-0000-0000-0000-000000000000";
        private const string RedirectUri = "urn%3AInstalledApplication";
        private readonly string _appliance;
        private readonly Form _form;
        private readonly WebBrowser _browser;

        public RstsWindow(string appliance)
        {
            _appliance = appliance;
            _form = new Form()
            {
                Text = $"{_appliance} - Safeguard Login",
                Width = 640,
                Height = 720,
                StartPosition = FormStartPosition.CenterParent
            };
            _browser = new WebBrowser() { Dock = DockStyle.Fill, AllowNavigation = true };
            _form.Controls.Add(_browser);
            _browser.DocumentTitleChanged += (sender, args) => {
                var b = (WebBrowser)sender;
                if (Regex.IsMatch(b.DocumentTitle, "error=[^&]*|code=[^&]*"))
                {
                    AuthorizationCode = b.DocumentTitle.Substring(5);
                    _form.DialogResult = DialogResult.OK;
                    _form.Hide();
                }
            };
        }
        public string AuthorizationCode { get; set; }
        public bool Show(string primaryProviderId = "", string secondaryProviderId = "")
        {
            try
            {
                string url;
                if (!string.IsNullOrEmpty(primaryProviderId) && !string.IsNullOrEmpty(secondaryProviderId))
                    url = string.Format("https://{0}/RSTS/Login?response_type=code&client_id={1}&redirect_uri={2}&primaryproviderid={3}&secondaryproviderid={4}",
                        _appliance, ClientId, RedirectUri, HttpUtility.UrlEncode(primaryProviderId), HttpUtility.UrlEncode(secondaryProviderId));
                else
                    url = string.Format("https://{0}/RSTS/Login?response_type=code&client_id={1}&redirect_uri={2}", _appliance, ClientId, RedirectUri);
                _browser.Stop();
                _browser.Navigate(url);
                return _form.ShowDialog() == DialogResult.OK;
            }
            catch (Exception e)
            {
                var color = Console.ForegroundColor; Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(e); Console.ForegroundColor = color;
                return false;
            }
        }
    }
}
