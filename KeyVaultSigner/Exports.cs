using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using KeyVaultSigner.Win32;
using Microsoft.Azure.KeyVault;

namespace KeyVaultSigner
{
    public static class Exports
    {
        [DllExport("AuthenticodeDigestSign", CallingConvention.Winapi)]
        public static uint AuthenticodeDigestSign([In] IntPtr pSignerCert,
                                                     [In] ref CRYPT_ATTR_BLOB pMetadataBlob,
                                                     [In] AlgId digestAlgID,
                                                     [In][MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 4)] byte[] pbToBeSignedDigest,
                                                     [In] int cbToBeSignedDigest,
                                                     [Out] out CRYPT_ATTR_BLOB pSignedDigest
                                                     )
        {


            var signerCert = new X509Certificate2(pSignerCert);
            var accessToken = Environment.GetEnvironmentVariable("KEYVAULT_ACCESSTOKEN");
            var keyVaultUrl = Environment.GetEnvironmentVariable("KEYVAULT_URL");
            var certificateName = Environment.GetEnvironmentVariable("KEYVAULT_CERTIFICATE_NAME");

            HookAssemblyLoad();

          
            pSignedDigest = default;

            var kvalg = AlgIdToJwsAlgId(digestAlgID);
            if (kvalg == null)
                return 1;

            var signed = SignWithKeyVault(keyVaultUrl, certificateName, accessToken, pbToBeSignedDigest, kvalg).Result;

            var buffer = Marshal.AllocHGlobal(signed.Length);
            Marshal.Copy(signed, 0, buffer, signed.Length);
            pSignedDigest = new CRYPT_ATTR_BLOB
            {
                pbData = buffer,
                cbData = signed.Length
            };
            
            return 0;
        }

        static async Task<byte[]> SignWithKeyVault(string keyVaultUrl, string certificateName, string accessToken, byte[] bytesToSign, string alg)
        {
            // We already have an access token for the resource
            Task<string> Authenticate(string authority, string resource, string scope)
            {
                return Task.FromResult(accessToken);
            }

            var client = new KeyVaultClient(Authenticate, new HttpClient());
            var kvcert = await client.GetCertificateAsync(keyVaultUrl, certificateName);


            var signed = await client.SignAsync(kvcert.KeyIdentifier.Identifier, alg, bytesToSign);

            return signed.Result;
        }

        static string AlgIdToJwsAlgId(AlgId algId)
        {
            if (algId == AlgId.CALG_SHA_256)
                return "RS256";

            if (algId == AlgId.CALG_SHA_384)
                return "RS384";

            if (algId == AlgId.CALG_SHA_512)
                return "RS512";

            Console.Error.WriteLine("Only sha256, sha384, and sha512 is supported by Azure Key Vault signing");
            return null;
        }

        static void HookAssemblyLoad()
        {
            AppDomain.CurrentDomain.AssemblyResolve += CurrentDomainOnAssemblyResolve;
        }

        static Assembly CurrentDomainOnAssemblyResolve(object sender, ResolveEventArgs args)
        {
            var shortName = args.Name.Split(',')[0] + ".dll";

            var thisDir = Path.GetDirectoryName(typeof(Exports).Assembly.Location);
            var toLoad = Path.Combine(thisDir, shortName);
            if (File.Exists(toLoad))
            {
                var assm = Assembly.LoadFrom(toLoad);
                return assm;
            }
            return null;
        }
        
    }
}
