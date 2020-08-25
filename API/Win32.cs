using System;
using System.Reflection;
using System.Runtime.InteropServices;



namespace SpDi2
{
    public static class Win32
    {
        public static bool VirtualProtect(IntPtr lpAddress, IntPtr dwSize, uint flNewProtect, ref uint lpflOldProtect)
        {
            object[] funcargs =
            {
                lpAddress, dwSize, flNewProtect, lpflOldProtect
            };

            bool retVal = (bool)Generic.DynamicAPIInvoke(@"k" + "e" + "r" + "n" + "e" + "l" + "3" + "2" + "." + "d" + "l" + "l", @"Vi" + "rt" + "ua" + "lP" + "ro" + "te" + "ct", typeof(Delegates.VirtualProtect), ref funcargs);

            lpflOldProtect = (uint)funcargs[3];

            return retVal;
        }

        public static uint VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress, ref SpDi.Win32.WinNT.PE_MEMORY_BASIC_INFORMATION lpBuffer, int dwLength)
        {
            object[] funcargs =
            {
                hProcess, lpAddress, lpBuffer, dwLength
           };

            return (uint)Generic.DynamicAPIInvoke(@"k" + "e" + "r" + "n" + "e" + "l" + "3" + "2" + "." + "d" + "l" + "l", @"Vi" + "rt" + "ua" + "lQ" + "ue" + "ry" + "Ex", typeof(Delegates.VirtualQueryEx), ref funcargs);
                    
        }

        public static IntPtr OpenProcess(SpDi.Win32.Kernel32.ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, UInt32 dwProcessId)
        {
            object[] funcargs =
            {
                dwDesiredAccess, bInheritHandle, dwProcessId
            };

            return (IntPtr)Generic.DynamicAPIInvoke(@"k" + "e" + "r" + "n" + "e" + "l" + "3" + "2" + "." + "d" + "l" + "l", @"Op" + "en" + "Pr" + "oc" + "ess", typeof(Delegates.OpenProcess), ref funcargs);
        }

        public static IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            ref IntPtr lpThreadId)
        {
            object[] funcargs =
            {
                hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId
            };

            IntPtr retValue = (IntPtr)Generic.DynamicAPIInvoke(@"k" + "e" + "r" + "n" + "e" + "l" + "3" + "2" + "." + "d" + "l" + "l", @"Cr" + "eat" + "e" + "Rem" + "ote" + "Thr" + "ead", typeof(Delegates.CreateRemoteThread), ref funcargs);

            lpThreadId = (IntPtr)funcargs[6];

            return retValue;
        }

        public static bool IsWow64Process(IntPtr hProcess, ref bool lpSystemInfo)
        {

            object[] funcargs =
            {
                hProcess, lpSystemInfo
            };

            bool retVal = (bool)Generic.DynamicAPIInvoke(@"k" + "e" + "r" + "n" + "e" + "l" + "3" + "2" + "." + "d" + "l" + "l", @"Is" + "Wow" + "64" + "Proc" + "ess", typeof(Delegates.IsWow64Process), ref funcargs);

            lpSystemInfo = (bool)funcargs[1];

            return retVal;
        }

        public static void GetSystemInfo(ref SpDi.Win32.Kernel32.PE_SYSTEM_INFO info)
        {
            object[] funcargs =
            {
                info
            };

            Generic.DynamicAPIInvoke(@"k" + "e" + "r" + "n" + "e" + "l" + "3" + "2" + "." + "d" + "l" + "l", @"Get" + "Sys" + "tem" + "In" + "fo", typeof(Delegates.GetSystemInfo), ref funcargs);

            info = (SpDi.Win32.Kernel32.PE_SYSTEM_INFO)funcargs[0];
        }

        public static void RtlFillMemory(IntPtr Destination, int Length, int Fill)
        {
            object[] funcargs =
            {
                Destination, Length, Fill
            };

            //Generic.DynamicAPIInvoke(@"k" + "e" + "r" + "n" + "e" + "l" + "3" + "2" + "." + "d" + "l" + "l", @"Rtl" + "Fill" + "Mem" + "ory", typeof(Delegates.RtlFillMemory), ref funcargs);
            var pointer = Generic.GetLibraryAddress(@"kernel32.dll", "RtlFillMemory");
            var fillMemory = Marshal.GetDelegateForFunctionPointer(pointer, typeof(Delegates.RtlFillMemory))as Delegates.RtlFillMemory;

        }

        public static bool ReadProcessMemory(IntPtr process, ulong address, byte[] buffer, ulong size, ref uint read)
        {
            object[] funcargs =
            {
                process, address, buffer, size, read
            };

            bool retVal = (bool)Generic.DynamicAPIInvoke(@"k" + "e" + "r" + "n" + "e" + "l" + "3" + "2" + "." + "d" + "l" + "l", @"Rea" + "dPr" + "oce" + "ss" + "Mem" + "ory", typeof(Delegates.ReadProcessMemory), ref funcargs);

            read = (uint)funcargs[3];

            return retVal;
        }

        public static class Delegates
        {
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr CreateRemoteThread(IntPtr hProcess,
                IntPtr lpThreadAttributes,
                uint dwStackSize,
                IntPtr lpStartAddress,
                IntPtr lpParameter,
                uint dwCreationFlags,
                out IntPtr lpThreadId);

            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate IntPtr OpenProcess(
                SpDi.Win32.Kernel32.ProcessAccessFlags dwDesiredAccess,
                bool bInheritHandle,
                UInt32 dwProcessId
            );

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool IsWow64Process(
                IntPtr hProcess, ref bool lpSystemInfo
            );

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate uint VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress, out SpDi.Win32.WinNT.PE_MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool VirtualProtect(IntPtr lpAddress, IntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void GetSystemInfo(ref SpDi.Win32.Kernel32.PE_SYSTEM_INFO info);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void RtlFillMemory(IntPtr Destination, int Length, int Fill);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool ReadProcessMemory(IntPtr process, ulong address, byte[] buffer, ulong size, ref uint read);
        }
    }
}
