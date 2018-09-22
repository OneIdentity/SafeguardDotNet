using System;
using System.Collections.Generic;
using System.Security;
using CommandLine;
using Newtonsoft.Json.Linq;
using OneIdentity.SafeguardDotNet;
using Serilog;

namespace SafeguardDotNetTool
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

        private static void Execute(ToolOptions opts)
        {
            try
            {
                var config = new LoggerConfiguration();
                config.WriteTo.ColoredConsole();

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

                JToken body = null;
                if (opts.Body != null)
                {
                    try
                    {
                        body = JToken.Parse(opts.Body);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e);
                        throw;
                    }
                }
                var responseBody = connection.InvokeMethod(opts.Service, opts.Method, opts.RelativeUrl, body, null, null);
                Log.Information(responseBody.ToString());
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
