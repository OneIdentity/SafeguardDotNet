using System;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OneIdentity.SafeguardDotNet
{
    internal static class CertificateUtilities
    {
        public static X509Certificate2 GetClientCertificateFromStore(string thumbprint)
        {
            try
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
                        store.Open(OpenFlags.ReadOnly);
                        cert = store.Certificates.OfType<X509Certificate2>()
                            .FirstOrDefault(x => x.Thumbprint == thumbprint);
                        if (cert == null)
                            throw new SafeguardDotNetException("Unable to find certificate matching " +
                                                               $"thumbprint={thumbprint} in Computer or User store");
                    }
                }
                return cert;
            }
            catch (Exception ex)
            {
                throw new SafeguardDotNetException($"Failure to get certificate from thumbprint={thumbprint}", ex);
            }
        }

        public static X509Certificate2 GetClientCertificateFromFile(string filepath, SecureString password)
        {
            try
            {
                return new X509Certificate2(filepath, password);
            }
            catch (Exception ex)
            {
                throw new SafeguardDotNetException($"Failure to get certificate from file={filepath}", ex);
            }
        }

        private static SecureString GenerateRandomSecureString(int size)
        {
            var secureString = new SecureString();
            using (var rng = new RNGCryptoServiceProvider())
            {
                var idx = 0;
                var data = new byte[size * 8];
                rng.GetBytes(data);
                for (var i = 0; i < size; i++)
                {
                    for (; idx < data.Length; idx++)
                    {
                        if (data[idx] > 0x20 && data[idx] < 127)
                        {
                            secureString.AppendChar((char)data[idx]);
                            data[idx] = 0x00;
                            break;
                        }
                        data[idx] = 0x00;
                    }
                    if (idx == data.Length)
                        throw new Exception("Failed to generate secure string with 8x key material");
                }
                Array.Clear(data, 0, data.Length);
            }
            return secureString;
        }

        public static X509Certificate2 Copy(X509Certificate2 certificate)
        {
            using (var password = GenerateRandomSecureString(24))
            {
                var export = certificate.Export(X509ContentType.Pkcs12, password);
                return new X509Certificate2(export, password,
                    X509KeyStorageFlags.DefaultKeySet | X509KeyStorageFlags.PersistKeySet);
            }
        }
    }
}
