using System;
using System.IO;
using System.Reflection;
using OneIdentity.SafeguardDotNet;
using Serilog;
using Serilog.Events;
using Topshelf;

namespace SampleA2aService
{
    static class Program
    {
        static void Main(string[] args)
        {
            if (Environment.UserInteractive)
                Log.Logger = new LoggerConfiguration().MinimumLevel.Debug().WriteTo.ColoredConsole()
                    .CreateLogger();
            else
            {
                var loggingDirectory = ConfigUtils.ReadRequiredSettingFromAppConfig("LoggingDirectory", "logging directory");
                if (!Path.IsPathRooted(loggingDirectory))
                    loggingDirectory = Path.Combine(Assembly.GetEntryAssembly().Location, loggingDirectory);
                Log.Logger = new LoggerConfiguration().WriteTo.RollingFile(
                        Path.Combine(loggingDirectory, "SampleA2aService-{Date}.log").ToString(),
                        LogEventLevel.Debug)
                    .CreateLogger();
            }

            HostFactory.Run(hostConfig =>
            {
                hostConfig.Service<SampleService>(service =>
                {
                    service.ConstructUsing(c => new SampleService());
                    service.WhenStarted(s => s.Start());
                    service.WhenStopped(s => s.Stop());
                });
                hostConfig.UseSerilog();
                hostConfig.StartAutomaticallyDelayed();
                hostConfig.SetDisplayName("SampleA2aService");
                hostConfig.SetServiceName("SampleA2aService");
                hostConfig.SetDescription("Simple application to notify when a password changes.");
            });
        }
    }
}
