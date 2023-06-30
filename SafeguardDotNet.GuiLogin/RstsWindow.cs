using System;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;
using System.Windows.Forms;
using Microsoft.Web.WebView2.WinForms;
using Serilog;

namespace OneIdentity.SafeguardDotNet.GuiLogin
{
    internal class RstsWindow
    {
        private const string RedirectUri = "urn:InstalledApplication";
        private readonly string _appliance;
        private readonly Form _form;
        private readonly WebView2 _browser;

        public string AuthorizationCode { get; set; }
        public string CodeVerifier { get; set; }

        public RstsWindow(string appliance)
        {
            _appliance = appliance;
            _form = new Form()
            {
                Text = $"{_appliance} - Safeguard Login",
                Width = 720,
                Height = 720,
                StartPosition = FormStartPosition.CenterParent
            };

            _browser = new WebView2() { Dock = DockStyle.Fill };
            _form.Controls.Add(_browser);

            _form.Load += async (s, e) => await InitializeAsync();
        }

        public async Task InitializeAsync()
        {
            _browser.CoreWebView2InitializationCompleted += CoreWebView2InitializationCompleted;

            await _browser.EnsureCoreWebView2Async(null);
            
            Log.Debug("WebView2 Runtime version: " + _browser.CoreWebView2.Environment.BrowserVersionString);
        }

        private void CoreWebView2InitializationCompleted(object sender, Microsoft.Web.WebView2.Core.CoreWebView2InitializationCompletedEventArgs e)
        {
            CodeVerifier = Safeguard.OAuthCodeVerifier();

            var url = $"https://{_appliance}/RSTS/Login?response_type=code&code_challenge_method=S256&code_challenge={Safeguard.OAuthCodeChallenge(CodeVerifier)}&redirect_uri={HttpUtility.UrlEncode(RedirectUri)}";

            _browser.Stop();
            _browser.CoreWebView2.DocumentTitleChanged += CoreWebView2_DocumentTitleChanged;
            _browser.CoreWebView2.Navigate(url);
        }

        private void CoreWebView2_DocumentTitleChanged(object sender, object e)
        {
            var b = sender as Microsoft.Web.WebView2.Core.CoreWebView2;

            if (Regex.IsMatch(b.DocumentTitle, "error=[^&]*|code=[^&]*"))
            {
                AuthorizationCode = b.DocumentTitle.Substring(5);
            }
            if (AuthorizationCode != null)
            {
                _form.DialogResult = DialogResult.OK;
                _form.Hide();
            }
        }

        public bool Show()
        {
            try
            {
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
