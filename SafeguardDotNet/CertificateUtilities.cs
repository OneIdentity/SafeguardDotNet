using System;
using System.Linq;
using System.Security;
using System.Security.Cryptography.X509Certificates;

namespace OneIdentity.SafeguardDotNet
{
    internal static class CertificateUtilities
    {
        public static X509Certificate2 GetClientCertificateFromStore(string thumbprint)
        {
            X509Certificate2 cert;
            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);
                cert = store.Certificates.OfType<X509Certificate2>()
                    .FirstOrDefault(x => x.Thumbprint == thumbprint);
            }
            if (cert == null)
            {
                using (var store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
                {


                    cert = store.Certificates.OfType<X509Certificate2>()
                        .FirstOrDefault(x => x.Thumbprint == thumbprint);
                    if (cert == null)
                        throw new Exception("Unable to find certificate matching " +
                                            $"thumbprint={thumbprint} in Computer or User store");
                }
            }
            return cert;
        }

        public static X509Certificate2 GetClientCertificateFromFile(string filepath, SecureString password)
        {
            try
            {
                return new X509Certificate2(filepath, password);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }
    }
}
