using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using KeyVaultSigner.Win32;

namespace KeyVaultSigner
{
    public static class Exports
    {
        [DllExport("AuthenticodeDigestSign", CallingConvention.Winapi)]
        public static uint AuthenticodeDigestSign([In] ref CERT_CONTEXT pSignerCert,
                                                     [In] ref CRYPT_ATTR_BLOB pMetadataBlob,
                                                     [In] AlgId digestAlgID,
                                                     [In][MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 4)] byte[] pbToBeSignedDigest,
                                                     [In] int cbToBeSignedDigest,
                                                     [Out] out CRYPT_ATTR_BLOB pSignedDigest
                                                     )
        {
           

            

            pSignedDigest = default;
            return 0;
        }
    }
}
