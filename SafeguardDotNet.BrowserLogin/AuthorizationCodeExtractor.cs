// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.BrowserLogin
{
    using System;
    using System.Net;
    using System.Net.Sockets;
    using System.Text;
    using System.Text.RegularExpressions;
    using System.Threading;
    using System.Web;

    public class AuthorizationCodeExtractor
    {
        public AuthorizationCodeExtractor()
        {
        }

        public string AuthorizationCode { get; set; }

        public void Listen(int port, CancellationToken cancellationToken)
        {
            var tcpListener = new TcpListener(IPAddress.Loopback, port);
            tcpListener.Start();

            try
            {
                var listenTask = tcpListener.AcceptTcpClientAsync().ContinueWith(async t =>
                {
                    if (t.IsFaulted || t.IsCanceled)
                    {
                        return null;
                    }

                    var tcpClient = t.Result;
                    using (var networkStream = tcpClient.GetStream())
                    {
                        var readBuffer = new byte[1024];
                        var sb = new StringBuilder();
                        do
                        {
                            var numberOfBytesRead = await networkStream.ReadAsync(readBuffer, 0, readBuffer.Length, cancellationToken).ConfigureAwait(false);
                            var s = Encoding.ASCII.GetString(readBuffer, 0, numberOfBytesRead);
                            sb.Append(s);
                        }
                        while (networkStream.DataAvailable);

                        var fullResponse =
                            "HTTP/1.1 200 OK\r\n\r\n<html><head><title>Authentication Complete</title></head><body><h2>Authentication complete.</h2>" +
                            "<p>You can return to your application.</p><p>Feel free to close this browser tab.</p></body></html>\r\n";
                        var response = Encoding.ASCII.GetBytes(fullResponse);
                        await networkStream.WriteAsync(response, 0, response.Length, cancellationToken);
                        await networkStream.FlushAsync(cancellationToken);
                        return sb.ToString();
                    }
                },
                cancellationToken);

                listenTask.Wait(cancellationToken);

                var innerTask = listenTask.Result;
                if (innerTask != null)
                {
                    innerTask.Wait(cancellationToken);

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
            }
            finally
            {
                tcpListener.Stop();
            }
        }

        private static string ExtractUriFromHttpRequest(string httpRequest)
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
