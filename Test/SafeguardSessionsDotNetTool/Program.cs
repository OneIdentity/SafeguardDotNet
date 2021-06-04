using System;
using System.IO;
using System.Collections.Generic;
using Serilog;
using Serilog.Sinks.SystemConsole.Themes;
using CommandLine;
using OneIdentity.SafeguardDotNet;

namespace SafeguardSessionsDotNetTool
{
  class Program
  {
    private static void Execute(ToolOptions options)
    {
      InitializeLogger(options);
      try {
        Log.Debug("Connecting to sps.");
        ISafeguardSessionsConnection connection = SafeguardForPrivilegedSessions.Connect(
            options.Address,
            options.Username,
            options.Password.ToSecureString(),
            options.Insecure);

        string responseBody;
        if (!string.IsNullOrEmpty(options.File)) {
          responseBody = File.ReadAllText(options.File);
        } else {
          responseBody = options.Body;
        }
        Log.Debug("Invoking method on sps.", options.Method, options.RelativeUrl, responseBody);

        FullResponse result = connection.InvokeMethodFull(
            options.Method,
            options.RelativeUrl,
            options.Body);

        Console.Write(result.Body);
      } catch (Exception ex) {
          Log.Error(ex, "Fatal exception occurred");
          Environment.Exit(1);
      }
    }

    private static void HandleParseError(IEnumerable<Error> errors)
    {
      Log.Error("Invalid command line options");
      Environment.Exit(1);
    }

    private static void InitializeLogger(ToolOptions options)
    {
      var config = new LoggerConfiguration();
      config.WriteTo.Console(outputTemplate: "{Message:lj}{NewLine}{Exception}", theme: AnsiConsoleTheme.Code);
      if (options.Verbose)
        config.MinimumLevel.Debug();
      else
        config.MinimumLevel.Information();
      Log.Logger = config.CreateLogger();
      Log.Debug("Logger initialized.");
    }

    static void Main(string[] args)
    {
      Parser.Default.ParseArguments<ToolOptions>(args)
        .WithParsed(Execute)
        .WithNotParsed(HandleParseError);
    }
  }
}
