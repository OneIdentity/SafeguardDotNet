// Copyright (c) One Identity LLC. All rights reserved.

// ReSharper disable InconsistentNaming
namespace OneIdentity.SafeguardDotNet
{
    internal class JoinRequest
    {
        public string spp { get; set; }

        public string spp_api_token { get; set; }

        public string spp_cert_chain { get; set; }
    }
}
