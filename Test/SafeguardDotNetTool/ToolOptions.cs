// Copyright (c) One Identity LLC. All rights reserved.

namespace SafeguardDotNetTool;

using System.Collections.Generic;

using CommandLine;

using OneIdentity.SafeguardDotNet;

internal class ToolOptions
{
    [Option(
        'a',
        "Appliance",
        Required = true,
        HelpText = "IP address or hostname of Safeguard appliance")]
    public string Appliance { get; set; }

    [Option(
        'x',
        "Insecure",
        Required = false,
        Default = false,
        HelpText = "Ignore validation of Safeguard appliance SSL certificate")]
    public bool Insecure { get; set; }

    [Option(
        'p',
        "ReadPassword",
        Required = false,
        Default = false,
        HelpText = "Read any required password from console stdin")]
    public bool ReadPassword { get; set; }

    [Option(
        'A',
        "Anonymous",
        Required = true,
        SetName = "AnonymousSet",
        HelpText = "Do not authenticate, call API anonymously")]
    public bool Anonymous { get; set; }

    [Option(
        'V',
        "Verbose",
        Required = false,
        Default = false,
        HelpText = "Display verbose debug output")]
    public bool Verbose { get; set; }

    [Option(
        'v',
        "ApiVersion",
        Required = false,
        Default = 4,
        HelpText = "Version of the Safeguard API to use")]
    public int ApiVersion { get; set; }

    [Option(
        'i',
        "IdentityProvider",
        Required = false,
        Default = null,
        SetName = "PasswordSet",
        HelpText = "Safeguard identity provider to use for rSTS")]
    public string IdentityProvider { get; set; }

    [Option(
        'u',
        "Username",
        Required = true,
        SetName = "PasswordSet",
        HelpText = "Safeguard username to use to authenticate")]
    public string Username { get; set; }

    [Option(
        't',
        "Thumbprint",
        Required = true,
        SetName = "CertificateThumbprint",
        HelpText = "Thumbprint for client certificate in user certificate store")]
    public string Thumbprint { get; set; }

    [Option(
        'c',
        "CertificateFile",
        Required = true,
        SetName = "CertificateFile",
        HelpText = "File path for client certificate")]
    public string CertificateFile { get; set; }

    [Option(
        'd',
        "CertificateAsData",
        Required = false,
        SetName = "CertificateFile",
        HelpText = "Create client certificate as data buffer")]
    public bool CertificateAsData { get; set; }

    [Option(
        'k',
        "AccessToken",
        Required = true,
        SetName = "AccessTokenSet",
        HelpText = "Pre-obtained access token for authentication")]
    public string AccessToken { get; set; }

    [Option(
        's',
        "Service",
        Required = false,
        HelpText = "Safeguard service to use (required for API invocation)")]
    public Service Service { get; set; }

    [Option(
        'm',
        "Method",
        Required = false,
        HelpText = "HTTP method to use (required for API invocation)")]
    public Method Method { get; set; }

    [Option(
        'U',
        "RelativeUrl",
        Required = false,
        HelpText = "API endpoint relative URL (required for API invocation)")]
    public string RelativeUrl { get; set; }

    [Option(
        'b',
        "Body",
        Required = false,
        Default = null,
        HelpText = "JSON body as string")]
    public string Body { get; set; }

    [Option(
        'B',
        "BodyFile",
        Required = false,
        Default = null,
        HelpText = "Path to a file containing the JSON body")]
    public string BodyFile { get; set; }

    [Option(
        'C',
        "Csv",
        Required = false,
        Default = null,
        HelpText = "Request for a response as CSV")]
    public bool Csv { get; set; }

    [Option(
        'f',
        "Full",
        Required = false,
        Default = false,
        HelpText = "Use InvokeMethodFull and output JSON envelope with StatusCode, Headers, and Body")]
    public bool Full { get; set; }

    [Option(
        'H',
        "Header",
        Required = false,
        Separator = ',',
        HelpText = "Additional HTTP headers as Key=Value pairs (comma-separated or repeated)")]
    public IEnumerable<string> Headers { get; set; }

    [Option(
        'P',
        "Parameter",
        Required = false,
        Separator = ',',
        HelpText = "Query parameters as Key=Value pairs (comma-separated or repeated)")]
    public IEnumerable<string> Parameters { get; set; }

    [Option(
        'F',
        "File",
        Required = false,
        Default = null,
        HelpText = "Path to a file to stream as the request body")]
    public string File { get; set; }

    [Option(
        'T',
        "TokenLifetime",
        Required = false,
        Default = false,
        HelpText = "Output token lifetime remaining (in minutes) as JSON and skip API invocation")]
    public bool TokenLifetime { get; set; }

    [Option(
        'R',
        "RefreshToken",
        Required = false,
        Default = false,
        HelpText = "Refresh the access token before API invocation or token lifetime output")]
    public bool RefreshToken { get; set; }

    [Option(
        'L',
        "Logout",
        Required = false,
        Default = false,
        HelpText = "Output the access token before logging out, to verify the token is invalidated")]
    public bool Logout { get; set; }

    [Option(
        'G',
        "GetToken",
        Required = false,
        Default = false,
        HelpText = "Output the current access token as JSON and exit without logging out")]
    public bool GetToken { get; set; }

    [Option(
        'Z',
        "Persist",
        Required = false,
        Default = false,
        HelpText = "Wrap connection with Safeguard.Persist() for automatic token refresh")]
    public bool Persist { get; set; }

    [Option(
        'W',
        "DelaySeconds",
        Required = false,
        Default = 0,
        HelpText = "Wait this many seconds after connecting before executing the operation")]
    public int DelaySeconds { get; set; }

    [Option(
        "MinTlsVersion",
        Required = false,
        Default = null,
        HelpText = "Minimum TLS version to negotiate: 1.2 or 1.3 (default lets the OS negotiate)")]
    public string MinTlsVersion { get; set; }

    [Option(
        "MaxTlsVersion",
        Required = false,
        Default = null,
        HelpText = "Maximum TLS version to negotiate: 1.2 or 1.3 (default lets the OS negotiate)")]
    public string MaxTlsVersion { get; set; }
}
