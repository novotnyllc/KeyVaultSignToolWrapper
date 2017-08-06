using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using KeyVaultSigner.Win32;

namespace KeyVaultSigner
{
    public static class Exports
    {
        [DllExport("AuthenticodeDigestSign", CallingConvention.Winapi)]
        public static uint AuthenticodeDigestSign([In] IntPtr pSignerCert,
                                                     [In] CRYPT_ATTR_BLOB pMetadataBlob,
                                                     [In] AlgId digestAlgID,
                                                     [In][MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 4)] byte[] pbToBeSignedDigest,
                                                     [In] int cbToBeSignedDigest,
                                                     [Out] out CRYPT_ATTR_BLOB pSignedDigest
                                                     )
        {


            var signerCert = new X509Certificate2(pSignerCert);

            pSignedDigest = default;
            return 0;
        }
    }
}
