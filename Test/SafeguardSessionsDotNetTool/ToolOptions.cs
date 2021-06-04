using CommandLine;
using OneIdentity.SafeguardDotNet;

namespace SafeguardSessionsDotNetTool
{
    internal class ToolOptions
    {
        [Option('a', "Address", Required = true,
            HelpText = "IP address or hostname of Safeguard for Privileged Sessions")]
        public string Address { get; set; }

        [Option('k', "Insecure", Required = false, Default = false,
            HelpText = "Ignore validation of SSL certificate")]
        public bool Insecure { get; set; }

        [Option('p', "Password", Required = true,
            HelpText = "Administrator password")]
        public string Password { get; set; }

        [Option('V', "Verbose", Required = false, Default = false,
            HelpText = "Display verbose debug output")]
        public bool Verbose { get; set; }

        [Option('u', "Username", Required = true,
            HelpText = "Admin username to use to authenticate")]
        public string Username { get; set; }

        [Option('m', "Method", Required = true,
            HelpText = "HTTP Method to use")]
        public Method Method { get; set; }

        [Option('U', "RelativeUrl", Required = true,
            HelpText = "HTTP Method to use")]
        public string RelativeUrl { get; set; }

        [Option('b', "Body", Required = false, Default = null,
            HelpText = "JSON body as string")]
        public string Body { get; set; }

        [Option('F', "File", Required = false, Default = null,
            HelpText = "Path to a file to stream as the request body")]
        public string File { get; set; }
    }
}
