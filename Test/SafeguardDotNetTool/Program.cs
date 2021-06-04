using System;
using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Threading;
using CommandLine;
using OneIdentity.SafeguardDotNet;
using Serilog;
using Serilog.Sinks.SystemConsole.Themes;

namespace SafeguardDotNetTool
{
    internal class Program
    {
        private static CancellationTokenSource Cts { get; } = new CancellationTokenSource();

        private static SecureString PromptForSecret(string name)
        {
            Console.Write($"{name}: ");
            var password = new SecureString();
            while (true)
            {
                var keyInput = Console.ReadKey(true);
                if (keyInput.Key == ConsoleKey.Enter)
                    break;
                if (keyInput.Key == ConsoleKey.Backspace)
                {
                    if (password.Length <= 0)
                        continue;
                    password.RemoveAt(password.Length - 1);
                    Console.Write("\b \b");
                }
                else
                {
                    password.AppendChar(keyInput.KeyChar);
                    Console.Write("*");
                }
            }
            Console.Write(Environment.NewLine);
            return password;
        }

        private static SecureString HandlePassword(bool readFromStdin)
        {
            return readFromStdin ? Console.ReadLine().ToSecureString() : PromptForSecret("Password");
        }

        private static void Execute(ToolOptions opts)
        {
            try
            {
                var config = new LoggerConfiguration();
                config.WriteTo.Console(outputTemplate: "{Message:lj}{NewLine}{Exception}", theme: AnsiConsoleTheme.Code);

                if (opts.Verbose)
                    config.MinimumLevel.Debug();
                else
                    config.MinimumLevel.Information();

                Log.Logger = config.CreateLogger();

                ISafeguardConnection connection;
                if (!string.IsNullOrEmpty(opts.Username))
                {
                    var password = HandlePassword(opts.ReadPassword);
                    connection = Safeguard.Connect(opts.Appliance, opts.IdentityProvider, opts.Username, password,
                        opts.ApiVersion, opts.Insecure);
                }
                else if (!string.IsNullOrEmpty(opts.CertificateFile))
                {
                    var password = HandlePassword(opts.ReadPassword);
                    if (opts.CertificateAsData)
                    {
                        var bytes = File.ReadAllBytes(opts.CertificateFile);
                        connection = Safeguard.Connect(opts.Appliance, bytes, password, opts.ApiVersion, opts.Insecure);
                    }
                    else
                    {
                        connection = Safeguard.Connect(opts.Appliance, opts.CertificateFile, password, opts.ApiVersion,
                            opts.Insecure);
                    }
                }
                else if (!string.IsNullOrEmpty(opts.Thumbprint))
                {
                    connection = Safeguard.Connect(opts.Appliance, opts.Thumbprint, opts.ApiVersion, opts.Insecure);
                }
                else if (opts.Anonymous)
                {
                    connection = Safeguard.Connect(opts.Appliance, opts.ApiVersion, opts.Insecure);
                }
                else
                {
                    throw new Exception("Must specify Anonymous, Username, CertificateFile, or Thumbprint");
                }

                Log.Debug($"Access Token Lifetime Remaining: {connection.GetAccessTokenLifetimeRemaining()}");

                string responseBody;
                if (!string.IsNullOrEmpty(opts.File))
                {
                    responseBody = HandleStreamingRequest(opts, connection);
                }
                else
                {
                    responseBody = opts.Csv
                    ? connection.InvokeMethodCsv(opts.Service, opts.Method, opts.RelativeUrl, opts.Body)
                    : connection.InvokeMethod(opts.Service, opts.Method, opts.RelativeUrl, opts.Body);
                }
                //Log.Information(responseBody); // if JSON is nested too deep Serilog swallows a '}' -- need to file issue with them
                Console.WriteLine(responseBody);

                connection.LogOut();
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Fatal exception occurred");
                Environment.Exit(1);
            }
        }

        private static string HandleStreamingRequest(ToolOptions opts, ISafeguardConnection connection)
        {
            if (opts.Method == Method.Post)
            {
                using FileStream fs = File.OpenRead(opts.File);
                var progress = opts.Verbose ? new Progress<TransferProgress>(p =>
                {
                    Console.Write("\rUploading: {0,3}% ({1}/{2})                                  ", p.PercentComplete, p.BytesTransferred, p.BytesTotal);
                }) : null;
                return connection.Streaming.UploadAsync(opts.Service, opts.RelativeUrl, fs, progress, cancellationToken: Cts.Token).Result;
            }
            else if (opts.Method == Method.Get)
            {
                if (File.Exists(opts.File))
                    throw new Exception($"File exists, remove it first: {opts.File}");
                var progress = opts.Verbose ? new Progress<TransferProgress>(p =>
                {
                    if (p.BytesTotal == 0)
                    {
                        Console.Write("\rDownloading: {0}", p.BytesTransferred);
                    }
                    else
                    {
                        Console.Write("\rDownloading: {0,3}% ({1}/{2})                                  ", p.PercentComplete, p.BytesTransferred, p.BytesTotal);
                    }
                }) : null;

                // This is the alternate way to download directly to a file:
                // connection.Streaming.DownloadAsync(opts.Service, opts.RelativeUrl, opts.File, progress: progress, cancellationToken: Cts.Token).Wait();

                using (var streamResult = connection.Streaming.DownloadStreamAsync(opts.Service, opts.RelativeUrl, progress: progress, cancellationToken: Cts.Token).Result)
                {
                    using (var fs = new FileStream(opts.File, FileMode.Create, FileAccess.ReadWrite))
                    {
                        var downloadStream = streamResult.GetStream().Result;
                        downloadStream.CopyToAsync(fs, 81920).Wait();
                    }
                }
                return $"Download written to {opts.File}";
            }
            else
            {
                throw new Exception($"Streaming is not supported for HTTP method: {opts.Method}");
            }
        }

        private static void HandleParseError(IEnumerable<Error> errors)
        {
            Log.Logger = new LoggerConfiguration().WriteTo.Console(theme: AnsiConsoleTheme.Code).CreateLogger();
            Log.Error("Invalid command line options");
            Environment.Exit(1);
        }

        private static void Main(string[] args)
        {
            Console.CancelKeyPress += delegate 
            {
                Cts.Cancel();
            };

            Parser.Default.ParseArguments<ToolOptions>(args)
                .WithParsed(Execute)
                .WithNotParsed(HandleParseError);
        }
    }
}
