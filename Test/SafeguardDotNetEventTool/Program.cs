using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using CommandLine;
using OneIdentity.SafeguardDotNet;
using OneIdentity.SafeguardDotNet.A2A;
using OneIdentity.SafeguardDotNet.Event;
using Serilog;
using Serilog.Sinks.SystemConsole.Themes;

namespace SafeguardDotNetEventTool
{
    internal class Program
    {
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

        public static bool CertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }

        private static List<SecureString> ReadAllApiKeys(ToolOptions opts, SecureString password)
        {
            var bytes = File.ReadAllBytes(opts.CertificateFile);
            using (var context = Safeguard.A2A.GetContext(opts.Appliance, bytes, password, CertificateValidationCallback, opts.ApiVersion))
            {
                return ReadAllApiKeys(context);
            }
        }

        private static List<SecureString> ReadAllApiKeys(ISafeguardA2AContext context)
        {
            var apiKeys = new List<SecureString>();
            var responseBody = context.GetRetrievableAccounts();
            foreach (var obj in responseBody)
            {
                Log.Information(obj.ToString());
                apiKeys.Add(obj.ApiKey);
            }

            return apiKeys;
        }

        private static ISafeguardEventListener CreatePersistentListener(ToolOptions opts)
        {
            if (!string.IsNullOrEmpty(opts.ApiKey))
            {
                void A2AHandler(string name, string body)
                {
                    Log.Information("Received A2AHandler Event: {EventBody}", body);
                }
                if (!string.IsNullOrEmpty(opts.CertificateFile))
                {
                    var password = HandlePassword(opts.ReadPassword);
                    if (opts.CertificateAsData)
                    {
                        var bytes = File.ReadAllBytes(opts.CertificateFile);

                        if (opts.ApiKey.Equals("?"))
                        {
                            var apiKeys = ReadAllApiKeys(opts, password);
                            if (opts.UseCertValidation)
                            {
                                return Safeguard.A2A.Event.GetPersistentA2AEventListener(apiKeys, A2AHandler, 
                                    opts.Appliance, bytes, password, CertificateValidationCallback, opts.ApiVersion);
                            }

                            return Safeguard.A2A.Event.GetPersistentA2AEventListener(apiKeys, A2AHandler, 
                                opts.Appliance, bytes, password, opts.ApiVersion, opts.Insecure);
                        }

                        if (!opts.ApiKey.Contains(','))
                        {
                            return Safeguard.A2A.Event.GetPersistentA2AEventListener(opts.ApiKey.ToSecureString(),
                                A2AHandler, opts.Appliance, bytes, password, opts.ApiVersion, opts.Insecure);
                        }

                        return Safeguard.A2A.Event.GetPersistentA2AEventListener(
                            opts.ApiKey.Split(',').Select(k => k.ToSecureString()), A2AHandler, opts.Appliance,
                            bytes, password, opts.ApiVersion, opts.Insecure);
                    }
                    if (!opts.ApiKey.Contains(','))
                        return Safeguard.A2A.Event.GetPersistentA2AEventListener(opts.ApiKey.ToSecureString(),
                            A2AHandler, opts.Appliance, opts.CertificateFile, password, opts.ApiVersion, opts.Insecure);
                    return Safeguard.A2A.Event.GetPersistentA2AEventListener(
                        opts.ApiKey.Split(',').Select(k => k.ToSecureString()), A2AHandler, opts.Appliance,
                        opts.CertificateFile, password, opts.ApiVersion, opts.Insecure);
                }
                if (!string.IsNullOrEmpty(opts.Thumbprint))
                {
                    if (!opts.ApiKey.Contains(','))
                        return Safeguard.A2A.Event.GetPersistentA2AEventListener(opts.ApiKey.ToSecureString(),
                            A2AHandler, opts.Appliance, opts.Thumbprint, opts.ApiVersion, opts.Insecure);
                    return Safeguard.A2A.Event.GetPersistentA2AEventListener(
                        opts.ApiKey.Split(',').Select(k => k.ToSecureString()), A2AHandler, opts.Appliance,
                        opts.Thumbprint, opts.ApiVersion, opts.Insecure);
                }
                throw new Exception("Must specify CertificateFile or Thumbprint");
            }

            if (string.IsNullOrEmpty(opts.Event))
                throw new Exception("You must specify the event name when not using A2A.");

            void Handler(string name, string body)
            {
                Log.Information("Received Safeguard Event: {EventBody}", body);
            }
            ISafeguardEventListener listener;
            if (!string.IsNullOrEmpty(opts.Username))
            {
                var password = HandlePassword(opts.ReadPassword);
                listener = Safeguard.Event.GetPersistentEventListener(opts.Appliance, opts.IdentityProvider, opts.Username,
                    password, opts.ApiVersion, opts.Insecure);
            }
            else if (!string.IsNullOrEmpty(opts.CertificateFile))
            {
                var password = HandlePassword(opts.ReadPassword);
                listener = Safeguard.Event.GetPersistentEventListener(opts.Appliance, opts.CertificateFile, password,
                    opts.ApiVersion, opts.Insecure);
            }
            else if (!string.IsNullOrEmpty(opts.Thumbprint))
            {
                listener = Safeguard.Event.GetPersistentEventListener(opts.Appliance, opts.Thumbprint, opts.ApiVersion,
                    opts.Insecure);
            }
            else
            {
                throw new Exception("Must specify Username, CertificateFile, or Thumbprint");
            }
            listener.RegisterEventHandler(opts.Event, Handler);
            return listener;
        }

        private static ISafeguardA2AContext CreateA2AContext(ToolOptions opts)
        {
            ISafeguardA2AContext context;
            if (!string.IsNullOrEmpty(opts.CertificateFile))
            {
                var password = HandlePassword(opts.ReadPassword);
                if (opts.UseCertValidation)
                {
                    var bytes = File.ReadAllBytes(opts.CertificateFile);
                    context = Safeguard.A2A.GetContext(opts.Appliance, bytes, password, CertificateValidationCallback, opts.ApiVersion);
                }
                else
                {
                    context = Safeguard.A2A.GetContext(opts.Appliance, opts.CertificateFile, password, opts.ApiVersion, opts.Insecure);
                }
            }
            else if (!string.IsNullOrEmpty(opts.Thumbprint))
            {
                context = Safeguard.A2A.GetContext(opts.Appliance, opts.Thumbprint, opts.ApiVersion, opts.Insecure);
            }
            else
            {
                throw new Exception("Must specify CertificateFile or Thumbprint");
            }
            return context;
        }

        private static ISafeguardEventListener CreateA2AListener(ToolOptions opts)
        {
            using (var context = CreateA2AContext(opts))
            {
                void A2AHandler(string name, string body)
                {
                    Log.Information("Received A2AHandler Event: {EventBody}", body);
                }
                if (opts.ApiKey.Equals("?"))
                {
                    var apiKeys = ReadAllApiKeys(context);
                    return context.GetA2AEventListener(apiKeys, A2AHandler);
                }

                if (!opts.ApiKey.Contains(','))
                    return context.GetA2AEventListener(opts.ApiKey.ToSecureString(), A2AHandler);

                return context.GetA2AEventListener(opts.ApiKey.Split(',').Select(k => k.ToSecureString()), A2AHandler);
            }
        }

        private static ISafeguardConnection CreateConnection(ToolOptions opts)
        {
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
                connection = Safeguard.Connect(opts.Appliance, opts.CertificateFile, password, opts.ApiVersion,
                    opts.Insecure);
            }
            else if (!string.IsNullOrEmpty(opts.Thumbprint))
            {
                connection = Safeguard.Connect(opts.Appliance, opts.Thumbprint, opts.ApiVersion, opts.Insecure);
            }
            else
            {
                throw new Exception("Must specify Username, CertificateFile, or Thumbprint");
            }
            return connection;
        }

        private static ISafeguardEventListener CreateEventListener(ToolOptions opts)
        {
            if (string.IsNullOrEmpty(opts.Event))
                throw new Exception("You must specify the event name when not using A2A.");
            using (var connection = CreateConnection(opts))
            {
                Log.Information(
                    $"Access Token Lifetime Remaining: {connection.GetAccessTokenLifetimeRemaining()}");
                var listener = connection.GetEventListener();
                listener.RegisterEventHandler(opts.Event, (name, body) =>
                {
                    Log.Information("Received Event: {EventName}", name);
                    Log.Information("Details: {EventBody}", body);
                });
                return listener;
            }
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

                void RunListener(ISafeguardEventListener listener)
                {
                    listener.Start();
                    Log.Information("Press any key to shut down the event listener...");
                    Console.ReadKey();
                    listener.Stop();
                }
                if (opts.Persistent)
                {
                    using (var listener = CreatePersistentListener(opts))
                        RunListener(listener);
                }
                else if (!string.IsNullOrEmpty(opts.ApiKey))
                {
                    using (var listener = CreateA2AListener(opts))
                        RunListener(listener);
                }
                else
                {
                    using (var listener = CreateEventListener(opts))
                        RunListener(listener);
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Fatal exception occurred");
                Environment.Exit(1);
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
            Parser.Default.ParseArguments<ToolOptions>(args)
                .WithParsed(Execute)
                .WithNotParsed(HandleParseError);
        }
    }
}
