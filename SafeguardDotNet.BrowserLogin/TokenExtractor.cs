using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web;

namespace OneIdentity.SafeguardDotNet.BrowserLogin
{
    internal class TokenExtractor
    {
        private readonly string _appliance;

        public TokenExtractor(string appliance)
        {
            _appliance = appliance;
        }

        public string AuthorizationCode { get; set; }
        public string CodeVerifier { get; set; }

        public bool Show(string username = "", int port = 8400)
        {
            CodeVerifier = Safeguard.OAuthCodeVerifier();

            var tcpListener = new TcpListener(IPAddress.Loopback, port);
            tcpListener.Start();
            var redirectUri = "urn:InstalledApplicationTcpListener";
            var accessTokenUri = $"https://{_appliance}/RSTS/Login?response_type=code&code_challenge_method=S256&code_challenge={Safeguard.OAuthCodeChallenge(CodeVerifier)}&redirect_uri={redirectUri}&port={port}";
           
            if (!string.IsNullOrEmpty(username))
                accessTokenUri += $"&login_hint={Uri.EscapeDataString(username)}";
            try
            {
                var psi = new ProcessStartInfo { FileName = accessTokenUri, UseShellExecute = true };
                Process.Start(psi);
            }
            catch (Exception ex)
            {
                // hack because of this: https://github.com/dotnet/corefx/issues/10361
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    accessTokenUri = accessTokenUri.Replace("&", "^&");
                    Process.Start(new ProcessStartInfo(accessTokenUri));
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    Process.Start("xdg-open", accessTokenUri);
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    Process.Start("open", accessTokenUri);
                }
                else
                {
                    throw new SafeguardDotNetException("Unable to launch default browser", ex);
                }
            }

            var source = new CancellationTokenSource();
            Console.CancelKeyPress += (sender, e) => { source.Cancel(); };
            try
            {
                var listenTask = tcpListener.AcceptTcpClientAsync().ContinueWith(async t =>
                {
                    if (t.IsFaulted || t.IsCanceled) return null;
                    var tcpClient = t.Result;
                    using (var networkStream = tcpClient.GetStream())
                    {
                        var readBuffer = new byte[1024];
                        var sb = new StringBuilder();
                        do
                        {
                            var numberOfBytesRead = await networkStream.ReadAsync(readBuffer, 0, readBuffer.Length, source.Token).ConfigureAwait(false);
                            var s = Encoding.ASCII.GetString(readBuffer, 0, numberOfBytesRead);
                            sb.Append(s);
                        } while (networkStream.DataAvailable);

                        var fullResponse =
                            "HTTP/1.1 200 OK\r\n\r\n<html><head><title>Authentication Complete</title></head><body><h2>Authentication complete.</h2>" +
                            "<p>You can return to your application.</p><p>Feel free to close this browser tab.</p></body></html>\r\n";
                        var response = Encoding.ASCII.GetBytes(fullResponse);
                        await networkStream.WriteAsync(response, 0, response.Length, source.Token);
                        await networkStream.FlushAsync(source.Token);
                        return sb.ToString();
                    }
                }, source.Token);

                listenTask.Wait(source.Token);

                var innerTask = listenTask.Result;
                if (innerTask != null)
                {
                    innerTask.Wait(source.Token);

                    if (!innerTask.IsFaulted && innerTask.Result != null)
                    {
                        AuthorizationCode = HttpUtility.ParseQueryString(ExtractUriFromHttpRequest(innerTask.Result)).Get("oauth");
                    }
                    else if (innerTask.Result != null)
                    {
                        throw new SafeguardDotNetException(innerTask.Result);
                    }
                    else
                    {
                        throw new SafeguardDotNetException("No HTTP redirect");
                    }
                }
                return true;
            }
            finally
            {
                tcpListener.Stop();
            }
        }

        private string ExtractUriFromHttpRequest(string httpRequest)
        {
            var regexp = @"GET \/\?(.*) HTTP";
            var r1 = new Regex(regexp);
            var match = r1.Match(httpRequest);
            if (!match.Success)
            {
                throw new SafeguardDotNetException("Redirect request is not a GET query");
            }
            return match.Groups[1].Value;
        }
    }
}
