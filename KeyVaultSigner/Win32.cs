using System;
using System.Runtime.InteropServices;

namespace KeyVaultSigner.Win32
{
    [StructLayout(LayoutKind.Sequential)]
    public struct CERT_CONTEXT
    {
        public uint dwCertEncodingType;
        public IntPtr pbCertEncoded;
        public int cbCertEncoded;
        public IntPtr pCertInfo;
        public IntPtr hCertStore;
        public CERT_INFO CertInfo => (CERT_INFO)Marshal.PtrToStructure(pCertInfo, typeof(CERT_INFO));

        public byte[] CertEncoded
        {
            get
            {
                var buffer = new byte[cbCertEncoded];
                Marshal.Copy(pbCertEncoded, buffer, 0, cbCertEncoded);
                return buffer;
            }
        }

    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CERT_INFO
    {
        public uint dwVersion;
        public CRYPT_ATTR_BLOB SerialNumber;
        public CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
        public CRYPT_ATTR_BLOB Issuer;
        public System.Runtime.InteropServices.ComTypes.FILETIME NotBefore;
        public System.Runtime.InteropServices.ComTypes.FILETIME NotAfter;
        public CRYPT_ATTR_BLOB Subject;
        public CERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo;
        public CRYPT_ATTR_BLOB IssuerUniqueId;
        public CRYPT_ATTR_BLOB SubjectUniqueId;
        public uint cExtension;
        public IntPtr rgExtension;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CRYPT_ATTR_BLOB
    {

        /// DWORD->unsigned int
        public int cbData;

        /// BYTE*
       // [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 0)]
        //public byte[] pbData;
        public IntPtr pbData;

        public byte[] Data
        {
            get
            {
                if (pbData == IntPtr.Zero)
                    return new byte[0];

                var buffer = new byte[cbData];
                Marshal.Copy(pbData, buffer, 0, cbData);
                return buffer;
            }
        }
    }


    [StructLayout(LayoutKind.Sequential)]
    public struct CERT_PUBLIC_KEY_INFO
    {

        /// CRYPT_ALGORITHM_IDENTIFIER->_CRYPT_ALGORITHM_IDENTIFIER
        public CRYPT_ALGORITHM_IDENTIFIER Algorithm;

        /// CRYPT_BIT_BLOB->_CRYPT_BIT_BLOB
        public CRYPT_BIT_BLOB PublicKey;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CRYPT_BIT_BLOB
    {

        /// DWORD->unsigned int
        public int cbData;

        //[MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 0)]
        //public byte[] pbData;
        public IntPtr pbData;

        /// DWORD->unsigned int
        public uint cUnusedBits;

        public byte[] Data
        {
            get
            {
                if (pbData == IntPtr.Zero)
                    return new byte[0];

                var buffer = new byte[cbData];
                Marshal.Copy(pbData, buffer, 0, cbData);
                return buffer;
            }
        }
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct CRYPT_ALGORITHM_IDENTIFIER
    {

        /// LPSTR->CHAR*
        [MarshalAs(UnmanagedType.LPStr)]
        public string pszObjId;

        /// CRYPT_OBJID_BLOB->_CRYPTOAPI_BLOB
        public CRYPT_ATTR_BLOB Parameters;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CERT_EXTENSION
    {

        /// LPSTR->CHAR*
        [MarshalAs(UnmanagedType.LPStr)]
        public string pszObjId;

        /// BOOL->int
        public int fCritical;

        /// CRYPT_OBJID_BLOB->_CRYPTOAPI_BLOB
        public CRYPT_ATTR_BLOB Value;
    }
}
