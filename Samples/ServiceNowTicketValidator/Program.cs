// Copyright (c) One Identity LLC. All rights reserved.

namespace ServiceNowTicketValidator
{
    using System;
    using System.IO;
    using System.Reflection;

    using Serilog;
    using Serilog.Events;
    using Topshelf;

    internal static class Program
    {
        private static void Main(string[] args)
        {
            if (Environment.UserInteractive)
            {
                Log.Logger = new LoggerConfiguration().MinimumLevel.Debug().WriteTo.Console()
                    .CreateLogger();
            }
            else
            {
                var loggingDirectory = ConfigUtils.ReadRequiredSettingFromAppConfig("LoggingDirectory", "logging directory");
                if (!Path.IsPathRooted(loggingDirectory))
                {
                    loggingDirectory = Path.Combine(Assembly.GetEntryAssembly().Location, loggingDirectory);
                }

                Log.Logger = new LoggerConfiguration().WriteTo.File(
                        Path.Combine(loggingDirectory, "ServiceNowTicketValidator-{Date}.log").ToString(),
                        LogEventLevel.Debug)
                    .CreateLogger();
            }

            HostFactory.Run(hostConfig =>
            {
                hostConfig.Service<ServiceNowTicketValidatorService>(service =>
                {
                    service.ConstructUsing(c => new ServiceNowTicketValidatorService());
                    service.WhenStarted(s => s.Start());
                    service.WhenStopped(s => s.Stop());
                });
                hostConfig.UseSerilog();
                hostConfig.StartAutomaticallyDelayed();
                hostConfig.SetDisplayName("ServiceNowTicketValidator");
                hostConfig.SetServiceName("SvcNowTktV");
                hostConfig.SetDescription("Simple ServiceNow ticket validation and access request approval engine.");
            });
        }
    }
}
