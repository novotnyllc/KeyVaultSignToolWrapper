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
        public static uint AuthenticodeDigestSign([In] IntPtr  pSignerCert,
                                                     [In] IntPtr  pMetadataBlob,
                                                     [In] AlgId digestAlgID,
                                                    // [In][MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 4)] byte[] pbToBeSignedDigest,
                                                     [In] IntPtr pbToBeSignedDigest,
                                                     [In] int cbToBeSignedDigest,
                                                     [Out] out CRYPT_ATTR_BLOB pSignedDigest
                                                     )
        {

            var digestToBeSigned = new byte[cbToBeSignedDigest];
            Marshal.Copy(pbToBeSignedDigest, digestToBeSigned, 0, cbToBeSignedDigest);


            

            pSignedDigest = default;
            return 0;
        }
    }
}
