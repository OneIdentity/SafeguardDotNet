using System;
using System.Collections.Generic;
using System.Security;
using CommandLine;
using OneIdentity.SafeguardDotNet;
using OneIdentity.SafeguardDotNet.A2A;
using OneIdentity.SafeguardDotNet.Event;
using Serilog;

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

        private static ISafeguardA2AContext CreateA2AContext(ToolOptions opts)
        {
            ISafeguardA2AContext context;
            if (!string.IsNullOrEmpty(opts.CertificateFile))
            {
                var password = HandlePassword(opts.ReadPassword);
                context = Safeguard.A2A.GetContext(opts.Appliance, opts.CertificateFile, password, opts.ApiVersion,
                    opts.Insecure);
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
                    return Safeguard.A2A.Event.GetPersistentA2AEventListener(opts.ApiKey.ToSecureString(), A2AHandler,
                        opts.Appliance, opts.CertificateFile, password, opts.ApiVersion, opts.Insecure);

                }
                if (!string.IsNullOrEmpty(opts.Thumbprint))
                    return Safeguard.A2A.Event.GetPersistentA2AEventListener(opts.ApiKey.ToSecureString(), A2AHandler,
                        opts.Appliance, opts.Thumbprint, opts.ApiVersion, opts.Insecure);
                throw new Exception("Must specify CertificateFile or Thumbprint");
            }
            void Handler(string name, string body)
            {
                Log.Information("Received A2A Event: {EventBody}", body);
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


        private static void Execute(ToolOptions opts)
        {
            try
            {
                var config = new LoggerConfiguration();
                config.WriteTo.ColoredConsole(outputTemplate: "{Message:lj}{NewLine}{Exception}");

                if (opts.Verbose)
                    config.MinimumLevel.Debug();
                else
                    config.MinimumLevel.Information();

                Log.Logger = config.CreateLogger();

                if (string.IsNullOrEmpty(opts.ApiKey))
                {
                    using (var connection = CreateConnection(opts))
                    {
                        Log.Information(
                            $"Access Token Lifetime Remaining: {connection.GetAccessTokenLifetimeRemaining()}");
                        using (var listener = connection.GetEventListener())
                        {
                            listener.RegisterEventHandler(opts.Event, (name, body) =>
                            {
                                Log.Information("Received Event: {EventName}", name);
                                Log.Information("Details: {EventBody}", body);
                            });
                            listener.Start();
                            Log.Information("Press any key to shut down the event listener...");
                            Console.ReadKey();
                            listener.Stop();
                        }
                    }
                }
                else
                {
                    if (opts.Persistent)
                    {
                        using (var listener = CreatePersistentListener(opts))
                        {
                            listener.Start();
                            Log.Information("Press any key to shut down the event listener...");
                            Console.ReadKey();
                            listener.Stop();
                        }
                    }
                    else
                    {
                        using (var context = CreateA2AContext(opts))
                        {
                            using (var listener = context.GetEventListener(opts.ApiKey.ToSecureString(), ((name, body) =>
                            {
                                Log.Information("Received A2A Event: {EventBody}", body);
                            })))
                            {
                                listener.Start();
                                Log.Information("Press any key to shut down the event listener...");
                                Console.ReadKey();
                                listener.Stop();
                            }
                        }
                    }
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
            Log.Logger = new LoggerConfiguration().WriteTo.ColoredConsole().CreateLogger();
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
