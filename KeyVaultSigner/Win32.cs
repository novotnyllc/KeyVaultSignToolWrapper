using System;
using System.Runtime.InteropServices;

namespace KeyVaultSigner.Win32
{
   
    [StructLayout(LayoutKind.Sequential)]
    public class CRYPT_ATTR_BLOB
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
}
