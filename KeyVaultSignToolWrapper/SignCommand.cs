using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using KeyVaultSignToolWrapper.PE;
using Microsoft.Azure.KeyVault;
using Microsoft.Extensions.CommandLineUtils;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace KeyVaultSignToolWrapper
{
    class SignCommand
    {
        readonly CommandLineApplication application;

        public SignCommand(CommandLineApplication application)
        {
            this.application = application;
        }
        
        public async Task<int> SignAsync(string signTool,
                                         string signToolArgs,
                                         string file,
                                         string keyVaultCertificateName,
                                         string keyVaultUrl,
                                         string keyVaultClientId,
                                         string keyVaultClientSecret,
                                         string keyVaultAccessToken)
        {
            /* We need to do a few things here.
             * 
             * 1. Get an access token if one is not provided. If one is provided, we assume it's valid.
             * 2. Download and save the certificate. We do this each time as a way to verify credentials and the certificate name
             * 3. Pass the location of the cert to SignTool via the -f parameter.
             * 4. Pass the file to sign for SignTool 
             * 
             */

            string validatedToken = null;
            
            async Task<string> Authenticate(string authority, string resource, string scope)
            {
                if (!string.IsNullOrWhiteSpace(keyVaultAccessToken))
                {
                    validatedToken = keyVaultAccessToken;
                    return keyVaultAccessToken;
                }

                var context = new AuthenticationContext(authority);
                var credential = new ClientCredential(keyVaultClientId, keyVaultClientSecret);

                var result = await context.AcquireTokenAsync(resource, credential).ConfigureAwait(false);
                if (result == null)
                {
                    throw new InvalidOperationException("Authentication to Azure failed.");
                }
                validatedToken = result.AccessToken;
                return result.AccessToken;
            }

            var client = new KeyVaultClient(Authenticate, new HttpClient());

            // We call this here to verify it's a valid cert
            // It also implicitly validates the access token or credentials
            var kvcert = await client.GetCertificateAsync(keyVaultUrl, keyVaultCertificateName).ConfigureAwait(false);

            var fileName = Path.Combine(Environment.GetEnvironmentVariable("TEMP"), "KeyVaultCerts", $"{keyVaultCertificateName}.cer");

            Directory.CreateDirectory(Path.GetDirectoryName(fileName));
            File.WriteAllBytes(fileName, kvcert.Cer);
            
            // path to our helper library
            var location = Path.GetDirectoryName(typeof(Program).Assembly.Location);
            var dir = new DirectoryInfo(location);

            // See if the signtool is x86 or x64
            var peReader = new PeHeaderReader(signTool);
            var platformDir = peReader.Is32BitHeader ? "x86" : "x64";

            var dlibLocation = Path.Combine(dir.FullName, platformDir, "KeyVaultSigner.dll");
            signToolArgs += $@" /dlib ""{dlibLocation}"" ";

            signToolArgs += $@" /f ""{fileName}"" ""{file}"" ";

            var psi = new ProcessStartInfo
            {
                FileName = signTool,
                Arguments = signToolArgs,
                CreateNoWindow = true,
                Environment =
                {
                    { "KEYVAULT_ACCESSTOKEN", validatedToken },
                    { "KEYVAULT_KEY_IDENTIFIER", kvcert.KeyIdentifier.Identifier }
                },
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                UseShellExecute = false
            };

            var process = Process.Start(psi);

            var output = process.StandardOutput.ReadToEnd();
            var error = process.StandardError.ReadToEnd();

            application.Out.Write(output);
            application.Error.WriteLine(error);
            process.WaitForExit();

            return process.ExitCode;
        }
    }
}
