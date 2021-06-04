using System;
using System.Collections.Generic;
using System.Linq;
using OneIdentity.SafeguardDotNet.Authentication;
using OneIdentity.SafeguardDotNet.Event;
using RestSharp;
using Serilog;

namespace OneIdentity.SafeguardDotNet
{
    internal class JoinRequest
    {
      public string spp { get; set; }
      public string spp_api_token { get; set; }
      public string spp_cert_chain { get; set; }
    };
}
