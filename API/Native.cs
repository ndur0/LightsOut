using System;
using System.Runtime.InteropServices;

using SpDi;

namespace SpDi2
{
    public class Native
    {
        public static SpDi.Native.NTSTATUS NtCreateThreadEx(
            ref IntPtr threadHandle,
            SpDi.Win32.WinNT.ACCESS_MASK desiredAccess,
            IntPtr objectAttributes,
            IntPtr processHandle,
            IntPtr startAddress,
            IntPtr parameter,
            bool createSuspended,
            int stackZeroBits,
            int sizeOfStack,
            int maximumStackSize,
            IntPtr attributeList)
        {
            object[] funcargs =
            {
                threadHandle, desiredAccess, objectAttributes, processHandle, startAddress, parameter, createSuspended, stackZeroBits,
                sizeOfStack, maximumStackSize, attributeList
            };

            SpDi.Native.NTSTATUS retValue = (SpDi.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtCreateThreadEx",
                typeof(DELEGATES.NtCreateThreadEx), ref funcargs);

            threadHandle = (IntPtr)funcargs[0];

            return retValue;
        }

        public static SpDi.Native.NTSTATUS RtlCreateUserThread(
                IntPtr Process,
                IntPtr ThreadSecurityDescriptor,
                bool CreateSuspended,
                IntPtr ZeroBits,
                IntPtr MaximumStackSize,
                IntPtr CommittedStackSize,
                IntPtr StartAddress,
                IntPtr Parameter,
                ref IntPtr Thread,
                IntPtr ClientId)
        {
            object[] funcargs =
            {
                Process, ThreadSecurityDescriptor, CreateSuspended, ZeroBits, 
                MaximumStackSize, CommittedStackSize, StartAddress, Parameter,
                Thread, ClientId
            };

            SpDi.Native.NTSTATUS retValue = (SpDi.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"RtlCreateUserThread",
                typeof(DELEGATES.RtlCreateUserThread), ref funcargs);

            Thread = (IntPtr)funcargs[8];

            return retValue;
        }

        public static SpDi.Native.NTSTATUS NtCreateSection(
            ref IntPtr SectionHandle,
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            ref ulong MaximumSize,
            uint SectionPageProtection,
            uint AllocationAttributes,
            IntPtr FileHandle)
        {

            object[] funcargs =
            {
                SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle
            };

            SpDi.Native.NTSTATUS retValue = (SpDi.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtCreateSection", typeof(DELEGATES.NtCreateSection), ref funcargs);
            if (retValue != SpDi.Native.NTSTATUS.Success)
            {
                throw new InvalidOperationException("Unable to create section, " + retValue);
            }

            SectionHandle = (IntPtr) funcargs[0];
            MaximumSize = (ulong) funcargs[3];

            return retValue;
        }

        public static SpDi.Native.NTSTATUS NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr)
        {
            object[] funcargs =
            {
                hProc, baseAddr
            };

            SpDi.Native.NTSTATUS result = (SpDi.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtUnmapViewOfSection",
                typeof(DELEGATES.NtUnmapViewOfSection), ref funcargs);

            return result;
        }

        public static SpDi.Native.NTSTATUS NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            IntPtr CommitSize,
            IntPtr SectionOffset,
            ref ulong ViewSize,
            uint InheritDisposition,
            uint AllocationType,
            uint Win32Protect)
        {

            object[] funcargs =
            {
                SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType,
                Win32Protect
            };

            SpDi.Native.NTSTATUS retValue = (SpDi.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtMapViewOfSection", typeof(DELEGATES.NtMapViewOfSection), ref funcargs);
            if (retValue != SpDi.Native.NTSTATUS.Success && retValue != SpDi.Native.NTSTATUS.ImageNotAtBase)
            {
                throw new InvalidOperationException("Unable to map view of section, " + retValue);
            }

            BaseAddress = (IntPtr) funcargs[2];
            ViewSize = (ulong) funcargs[6];

            return retValue;
        }

        public static void RtlInitUnicodeString(ref SpDi.Native.UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString)
        {
            object[] funcargs =
            {
                DestinationString, SourceString
            };

            Generic.DynamicAPIInvoke(@"ntdll.dll", @"RtlInitUnicodeString", typeof(DELEGATES.RtlInitUnicodeString), ref funcargs);

            DestinationString = (SpDi.Native.UNICODE_STRING)funcargs[0];
        }

        public static SpDi.Native.NTSTATUS LdrLoadDll(IntPtr PathToFile, UInt32 dwFlags, ref SpDi.Native.UNICODE_STRING ModuleFileName, ref IntPtr ModuleHandle)
        {
            object[] funcargs =
            {
                PathToFile, dwFlags, ModuleFileName, ModuleHandle
            };

            SpDi.Native.NTSTATUS retValue = (SpDi.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"LdrLoadDll", typeof(DELEGATES.LdrLoadDll), ref funcargs);

            ModuleHandle = (IntPtr)funcargs[3];

            return retValue;
        }

        public static void RtlZeroMemory(IntPtr Destination, int Length)
        {
            object[] funcargs =
            {
                Destination, Length
            };

            Generic.DynamicAPIInvoke(@"ntdll.dll", @"RtlZeroMemory", typeof(DELEGATES.RtlZeroMemory), ref funcargs);
        }

        public static void RtlFillMemory(IntPtr Destination, int Length, int Fill)
        {
            object[] funcargs =
            {
                Destination, Length, Fill
            };

            Generic.DynamicAPIInvoke(@"ntdll.dll", @"RtlFillMemory", typeof(DELEGATES.RtlFillMemory), ref funcargs);
        }

        public static SpDi.Native.NTSTATUS NtQueryInformationProcess(IntPtr hProcess, SpDi.Native.PROCESSINFOCLASS processInfoClass, out IntPtr pProcInfo)
        {
            int processInformationLength;
            UInt32 RetLen = 0;

            switch (processInfoClass)
            {
                case SpDi.Native.PROCESSINFOCLASS.ProcessWow64Information:
                    pProcInfo = Marshal.AllocHGlobal(IntPtr.Size);
                    RtlZeroMemory(pProcInfo, IntPtr.Size);
                    processInformationLength = IntPtr.Size;
                    break;
                case SpDi.Native.PROCESSINFOCLASS.ProcessBasicInformation:
                    SpDi.Native.PROCESS_BASIC_INFORMATION PBI = new SpDi.Native.PROCESS_BASIC_INFORMATION();
                    pProcInfo = Marshal.AllocHGlobal(Marshal.SizeOf(PBI));
                    RtlZeroMemory(pProcInfo, Marshal.SizeOf(PBI));
                    Marshal.StructureToPtr(PBI, pProcInfo, true);
                    processInformationLength = Marshal.SizeOf(PBI);
                    break;
                default:
                    throw new InvalidOperationException($"Invalid ProcessInfoClass: {processInfoClass}");
            }

            object[] funcargs =
            {
                hProcess, processInfoClass, pProcInfo, processInformationLength, RetLen
            };

            SpDi.Native.NTSTATUS retValue = (SpDi.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtQueryInformationProcess", typeof(DELEGATES.NtQueryInformationProcess), ref funcargs);
            if (retValue != SpDi.Native.NTSTATUS.Success)
            {
                throw new UnauthorizedAccessException("Access is denied.");
            }

            pProcInfo = (IntPtr)funcargs[2];

            return retValue;
        }

        public static bool NtQueryInformationProcessWow64Information(IntPtr hProcess)
        {
            SpDi.Native.NTSTATUS retValue = NtQueryInformationProcess(hProcess, SpDi.Native.PROCESSINFOCLASS.ProcessWow64Information, out IntPtr pProcInfo);
            if (retValue != SpDi.Native.NTSTATUS.Success)
            {
                throw new UnauthorizedAccessException("Access is denied.");
            }

            if (Marshal.ReadIntPtr(pProcInfo) == IntPtr.Zero)
            {
                return false;
            }
            return true;
        }

        public static SpDi.Native.PROCESS_BASIC_INFORMATION NtQueryInformationProcessBasicInformation(IntPtr hProcess)
        {
            SpDi.Native.NTSTATUS retValue = NtQueryInformationProcess(hProcess, SpDi.Native.PROCESSINFOCLASS.ProcessBasicInformation, out IntPtr pProcInfo);
            if (retValue != SpDi.Native.NTSTATUS.Success)
            {
                throw new UnauthorizedAccessException("Access is denied.");
            }

            return (SpDi.Native.PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(pProcInfo, typeof(SpDi.Native.PROCESS_BASIC_INFORMATION));
        }

        public static IntPtr NtOpenProcess(UInt32 ProcessId, SpDi.Win32.Kernel32.ProcessAccessFlags DesiredAccess)
        {
            IntPtr ProcessHandle = IntPtr.Zero;
            SpDi.Native.OBJECT_ATTRIBUTES oa = new SpDi.Native.OBJECT_ATTRIBUTES();
            SpDi.Native.CLIENT_ID ci = new SpDi.Native.CLIENT_ID();
            ci.UniqueProcess = (IntPtr)ProcessId;

            object[] funcargs =
            {
                ProcessHandle, DesiredAccess, oa, ci
            };

            SpDi.Native.NTSTATUS retValue = (SpDi.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtOpenProcess", typeof(DELEGATES.NtOpenProcess), ref funcargs);
            if (retValue != SpDi.Native.NTSTATUS.Success && retValue == SpDi.Native.NTSTATUS.InvalidCid)
            {
                throw new InvalidOperationException("An invalid client ID was specified.");
            }
            if (retValue != SpDi.Native.NTSTATUS.Success)
            {
                throw new UnauthorizedAccessException("Access is denied.");
            }

            ProcessHandle = (IntPtr)funcargs[0];

            return ProcessHandle;
        }

        public static void NtQueueApcThread(IntPtr ThreadHandle, IntPtr ApcRoutine, IntPtr ApcArgument1, IntPtr ApcArgument2, IntPtr ApcArgument3)
        {
            object[] funcargs =
            {
                ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3
            };

            SpDi.Native.NTSTATUS retValue = (SpDi.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtQueueApcThread", typeof(DELEGATES.NtQueueApcThread), ref funcargs);
            if (retValue != SpDi.Native.NTSTATUS.Success)
            {
                throw new InvalidOperationException("Unable to queue APC, " + retValue);
            }
        }

        public static IntPtr NtOpenThread(int TID, SpDi.Win32.Kernel32.ThreadAccess DesiredAccess)
        {
            IntPtr ThreadHandle = IntPtr.Zero;
            SpDi.Native.OBJECT_ATTRIBUTES oa = new SpDi.Native.OBJECT_ATTRIBUTES();
            SpDi.Native.CLIENT_ID ci = new SpDi.Native.CLIENT_ID();
            ci.UniqueThread = (IntPtr)TID;

            object[] funcargs =
            {
                ThreadHandle, DesiredAccess, oa, ci
            };

            SpDi.Native.NTSTATUS retValue = (SpDi.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtOpenThread", typeof(DELEGATES.NtOpenProcess), ref funcargs);
            if (retValue != SpDi.Native.NTSTATUS.Success && retValue == SpDi.Native.NTSTATUS.InvalidCid)
            {
                throw new InvalidOperationException("An invalid client ID was specified.");
            }
            if (retValue != SpDi.Native.NTSTATUS.Success)
            {
                throw new UnauthorizedAccessException("Access is denied.");
            }

            ThreadHandle = (IntPtr)funcargs[0];

            return ThreadHandle;
        }

        public static IntPtr NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, UInt32 AllocationType, UInt32 Protect)
        {
            object[] funcargs =
            {
                ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect
            };

            SpDi.Native.NTSTATUS retValue = (SpDi.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtAllocateVirtualMemory", typeof(DELEGATES.NtAllocateVirtualMemory), ref funcargs);
            if (retValue == SpDi.Native.NTSTATUS.AccessDenied)
            {
                throw new UnauthorizedAccessException("Access is denied.");
            }
            if (retValue == SpDi.Native.NTSTATUS.AlreadyCommitted)
            {
                throw new InvalidOperationException("The specified address range is already committed.");
            }
            if (retValue == SpDi.Native.NTSTATUS.CommitmentLimit)
            {
                throw new InvalidOperationException("Your system is low on virtual memory.");
            }
            if (retValue == SpDi.Native.NTSTATUS.ConflictingAddresses)
            {
                throw new InvalidOperationException("The specified address range conflicts with the address space.");
            }
            if (retValue == SpDi.Native.NTSTATUS.InsufficientResources)
            {
                throw new InvalidOperationException("Insufficient system resources exist to complete the API call.");
            }
            if (retValue == SpDi.Native.NTSTATUS.InvalidHandle)
            {
                throw new InvalidOperationException("An invalid HANDLE was specified.");
            }
            if (retValue == SpDi.Native.NTSTATUS.InvalidPageProtection)
            {
                throw new InvalidOperationException("The specified page protection was not valid.");
            }
            if (retValue == SpDi.Native.NTSTATUS.NoMemory)
            {
                throw new InvalidOperationException("Not enough virtual memory or paging file quota is available to complete the specified operation.");
            }
            if (retValue == SpDi.Native.NTSTATUS.ObjectTypeMismatch)
            {
                throw new InvalidOperationException("There is a mismatch between the type of object that is required by the requested operation and the type of object that is specified in the request.");
            }
            if (retValue != SpDi.Native.NTSTATUS.Success)
            {
                throw new InvalidOperationException("An attempt was made to duplicate an object handle into or out of an exiting process.");
            }

            BaseAddress = (IntPtr)funcargs[1];
            return BaseAddress;
        }

        public static void NtFreeVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, UInt32 FreeType)
        {
            object[] funcargs =
            {
                ProcessHandle, BaseAddress, RegionSize, FreeType
            };

            SpDi.Native.NTSTATUS retValue = (SpDi.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtFreeVirtualMemory", typeof(DELEGATES.NtFreeVirtualMemory), ref funcargs);
            if (retValue == SpDi.Native.NTSTATUS.AccessDenied)
            {
                throw new UnauthorizedAccessException("Access is denied.");
            }
            if (retValue == SpDi.Native.NTSTATUS.InvalidHandle)
            {
                throw new InvalidOperationException("An invalid HANDLE was specified.");
            }
            if (retValue != SpDi.Native.NTSTATUS.Success)
            {
                throw new InvalidOperationException("There is a mismatch between the type of object that is required by the requested operation and the type of object that is specified in the request.");
            }
        }

        public static string GetFilenameFromMemoryPointer(IntPtr hProc, IntPtr pMem)
        {
            IntPtr pBase = IntPtr.Zero;
            IntPtr RegionSize = (IntPtr)0x500;
            IntPtr pAlloc = NtAllocateVirtualMemory(hProc, ref pBase, IntPtr.Zero, ref RegionSize, SpDi.Win32.Kernel32.MEM_COMMIT | SpDi.Win32.Kernel32.MEM_RESERVE, SpDi.Win32.WinNT.PAGE_READWRITE);

            SpDi.Native.MEMORYINFOCLASS memoryInfoClass = SpDi.Native.MEMORYINFOCLASS.MemorySectionName;
            UInt32 MemoryInformationLength = 0x500;
            UInt32 Retlen = 0;

            object[] funcargs =
            {
                hProc, pMem, memoryInfoClass, pAlloc, MemoryInformationLength, Retlen
            };

            SpDi.Native.NTSTATUS retValue = (SpDi.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtQueryVirtualMemory", typeof(DELEGATES.NtQueryVirtualMemory), ref funcargs);

            string FilePath = string.Empty;
            if (retValue == SpDi.Native.NTSTATUS.Success)
            {
                SpDi.Native.UNICODE_STRING sn = (SpDi.Native.UNICODE_STRING)Marshal.PtrToStructure(pAlloc, typeof(SpDi.Native.UNICODE_STRING));
                FilePath = Marshal.PtrToStringUni(sn.Buffer);
            }

            NtFreeVirtualMemory(hProc, ref pAlloc, ref RegionSize, SpDi.Win32.Kernel32.MEM_RELEASE);
            if (retValue == SpDi.Native.NTSTATUS.AccessDenied)
            {
                throw new UnauthorizedAccessException("Access is denied.");
            }
            if (retValue == SpDi.Native.NTSTATUS.AccessViolation)
            {
                throw new InvalidOperationException("The specified base address is an invalid virtual address.");
            }
            if (retValue == SpDi.Native.NTSTATUS.InfoLengthMismatch)
            {
                throw new InvalidOperationException("The MemoryInformation buffer is larger than MemoryInformationLength.");
            }
            if (retValue == SpDi.Native.NTSTATUS.InvalidParameter)
            {
                throw new InvalidOperationException("The specified base address is outside the range of accessible addresses.");
            }
            return FilePath;
        }

        public static UInt32 NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, UInt32 NewProtect)
        {
            UInt32 OldProtect = 0;
            object[] funcargs =
            {
                ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect
            };

            SpDi.Native.NTSTATUS retValue = (SpDi.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtProtectVirtualMemory", typeof(DELEGATES.NtProtectVirtualMemory), ref funcargs);
            if (retValue != SpDi.Native.NTSTATUS.Success)
            {
                throw new InvalidOperationException("Failed to change memory protection, " + retValue);
            }

            OldProtect = (UInt32)funcargs[4];
            return OldProtect;
        }

        public static UInt32 NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr Buffer, UInt32 BufferLength)
        {
            UInt32 BytesWritten = 0;
            object[] funcargs =
            {
                ProcessHandle, BaseAddress, Buffer, BufferLength, BytesWritten
            };

            SpDi.Native.NTSTATUS retValue = (SpDi.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtWriteVirtualMemory", typeof(DELEGATES.NtWriteVirtualMemory), ref funcargs);
            if (retValue != SpDi.Native.NTSTATUS.Success)
            {
                throw new InvalidOperationException("Failed to write memory, " + retValue);
            }

            BytesWritten = (UInt32)funcargs[4];
            return BytesWritten;
        }

        public static IntPtr LdrGetProcedureAddress(IntPtr hModule, IntPtr FunctionName, IntPtr Ordinal, ref IntPtr FunctionAddress)
        {
            object[] funcargs =
            {
                hModule, FunctionName, Ordinal, FunctionAddress
            };

            SpDi.Native.NTSTATUS retValue = (SpDi.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"LdrGetProcedureAddress", typeof(DELEGATES.LdrGetProcedureAddress), ref funcargs);
            if (retValue != SpDi.Native.NTSTATUS.Success)
            {
                throw new InvalidOperationException("Failed get procedure address, " + retValue);
            }

            FunctionAddress = (IntPtr)funcargs[3];
            return FunctionAddress;
        }

        public static void RtlGetVersion(ref SpDi.Native.OSVERSIONINFOEX VersionInformation)
        {
            object[] funcargs =
            {
                VersionInformation
            };

            SpDi.Native.NTSTATUS retValue = (SpDi.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"RtlGetVersion", typeof(DELEGATES.RtlGetVersion), ref funcargs);
            if (retValue != SpDi.Native.NTSTATUS.Success)
            {
                throw new InvalidOperationException("Failed get procedure address, " + retValue);
            }

            VersionInformation = (SpDi.Native.OSVERSIONINFOEX)funcargs[0];
        }

        public static UInt32 NtReadVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr Buffer, ref UInt32 NumberOfBytesToRead)
        {
            UInt32 NumberOfBytesRead = 0;
            object[] funcargs =
            {
                ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead
            };

            SpDi.Native.NTSTATUS retValue = (SpDi.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtReadVirtualMemory", typeof(DELEGATES.NtReadVirtualMemory), ref funcargs);
            if (retValue != SpDi.Native.NTSTATUS.Success)
            {
                throw new InvalidOperationException("Failed to read memory, " + retValue);
            }

            NumberOfBytesRead = (UInt32)funcargs[4];
            return NumberOfBytesRead;
        }

        public static IntPtr NtOpenFile(ref IntPtr FileHandle, SpDi.Win32.Kernel32.FileAccessFlags DesiredAccess, ref SpDi.Native.OBJECT_ATTRIBUTES ObjAttr, ref SpDi.Native.IO_STATUS_BLOCK IoStatusBlock, SpDi.Win32.Kernel32.FileShareFlags ShareAccess, SpDi.Win32.Kernel32.FileOpenFlags OpenOptions)
        {
            object[] funcargs =
            {
                FileHandle, DesiredAccess, ObjAttr, IoStatusBlock, ShareAccess, OpenOptions
            };

            SpDi.Native.NTSTATUS retValue = (SpDi.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"ntdll.dll", @"NtOpenFile", typeof(DELEGATES.NtOpenFile), ref funcargs);
            if (retValue != SpDi.Native.NTSTATUS.Success)
            {
                throw new InvalidOperationException("Failed to open file, " + retValue);
            }


            FileHandle = (IntPtr)funcargs[0];
            return FileHandle;
        }

        public struct DELEGATES
        {
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate SpDi.Native.NTSTATUS NtCreateThreadEx(
                out IntPtr threadHandle,
                SpDi.Win32.WinNT.ACCESS_MASK desiredAccess,
                IntPtr objectAttributes,
                IntPtr processHandle,
                IntPtr startAddress,
                IntPtr parameter,
                bool createSuspended,
                int stackZeroBits,
                int sizeOfStack,
                int maximumStackSize,
                IntPtr attributeList);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate SpDi.Native.NTSTATUS RtlCreateUserThread(
                IntPtr Process,
                IntPtr ThreadSecurityDescriptor,
                bool CreateSuspended,
                IntPtr ZeroBits,
                IntPtr MaximumStackSize,
                IntPtr CommittedStackSize,
                IntPtr StartAddress,
                IntPtr Parameter,
                ref IntPtr Thread,
                IntPtr ClientId);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate SpDi.Native.NTSTATUS NtCreateSection(
                ref IntPtr SectionHandle,
                uint DesiredAccess,
                IntPtr ObjectAttributes,
                ref ulong MaximumSize,
                uint SectionPageProtection,
                uint AllocationAttributes,
                IntPtr FileHandle);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate SpDi.Native.NTSTATUS NtUnmapViewOfSection(
                IntPtr hProc,
                IntPtr baseAddr);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate SpDi.Native.NTSTATUS NtMapViewOfSection(
                IntPtr SectionHandle,
                IntPtr ProcessHandle,
                out IntPtr BaseAddress,
                IntPtr ZeroBits,
                IntPtr CommitSize,
                IntPtr SectionOffset,
                out ulong ViewSize,
                uint InheritDisposition,
                uint AllocationType,
                uint Win32Protect);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 LdrLoadDll(
                IntPtr PathToFile,
                UInt32 dwFlags,
                ref SpDi.Native.UNICODE_STRING ModuleFileName,
                ref IntPtr ModuleHandle);
            
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void RtlInitUnicodeString(
                ref SpDi.Native.UNICODE_STRING DestinationString,
                [MarshalAs(UnmanagedType.LPWStr)]
                string SourceString);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void RtlZeroMemory(
                IntPtr Destination,
                int length);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void RtlFillMemory(
                IntPtr Destination,
                int Length,
                int Fill);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 NtQueryInformationProcess(
                IntPtr processHandle,
                SpDi.Native.PROCESSINFOCLASS processInformationClass,
                IntPtr processInformation,
                int processInformationLength,
                ref UInt32 returnLength);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 NtOpenProcess(
                ref IntPtr ProcessHandle,
                SpDi.Win32.Kernel32.ProcessAccessFlags DesiredAccess,
                ref SpDi.Native.OBJECT_ATTRIBUTES ObjectAttributes,
                ref SpDi.Native.CLIENT_ID ClientId);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 NtQueueApcThread(
                IntPtr ThreadHandle,
                IntPtr ApcRoutine,
                IntPtr ApcArgument1,
                IntPtr ApcArgument2,
                IntPtr ApcArgument3);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 NtOpenThread(
                ref IntPtr ThreadHandle,
                SpDi.Win32.Kernel32.ThreadAccess DesiredAccess,
                ref SpDi.Native.OBJECT_ATTRIBUTES ObjectAttributes,
                ref SpDi.Native.CLIENT_ID ClientId);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 NtAllocateVirtualMemory(
                IntPtr ProcessHandle,
                ref IntPtr BaseAddress,
                IntPtr ZeroBits,
                ref IntPtr RegionSize,
                UInt32 AllocationType,
                UInt32 Protect);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 NtFreeVirtualMemory(
                IntPtr ProcessHandle,
                ref IntPtr BaseAddress,
                ref IntPtr RegionSize,
                UInt32 FreeType);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 NtQueryVirtualMemory(
                IntPtr ProcessHandle,
                IntPtr BaseAddress,
                SpDi.Native.MEMORYINFOCLASS MemoryInformationClass,
                IntPtr MemoryInformation,
                UInt32 MemoryInformationLength,
                ref UInt32 ReturnLength);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 NtProtectVirtualMemory(
                IntPtr ProcessHandle,
                ref IntPtr BaseAddress,
                ref IntPtr RegionSize,
                UInt32 NewProtect,
                ref UInt32 OldProtect);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 NtWriteVirtualMemory(
                IntPtr ProcessHandle,
                IntPtr BaseAddress,
                IntPtr Buffer,
                UInt32 BufferLength,
                ref UInt32 BytesWritten);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 RtlUnicodeStringToAnsiString(
                ref SpDi.Native.ANSI_STRING DestinationString,
                ref SpDi.Native.UNICODE_STRING SourceString,
                bool AllocateDestinationString);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 LdrGetProcedureAddress(
                IntPtr hModule,
                IntPtr FunctionName,
                IntPtr Ordinal,
                ref IntPtr FunctionAddress);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 RtlGetVersion(
                ref SpDi.Native.OSVERSIONINFOEX VersionInformation);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 NtReadVirtualMemory(
                IntPtr ProcessHandle,
                IntPtr BaseAddress,
                IntPtr Buffer,
                UInt32 NumberOfBytesToRead,
                ref UInt32 NumberOfBytesRead);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 NtOpenFile(
                ref IntPtr FileHandle,
                SpDi.Win32.Kernel32.FileAccessFlags DesiredAccess,
                ref SpDi.Native.OBJECT_ATTRIBUTES ObjAttr,
                ref SpDi.Native.IO_STATUS_BLOCK IoStatusBlock,
                SpDi.Win32.Kernel32.FileShareFlags ShareAccess,
                SpDi.Win32.Kernel32.FileOpenFlags OpenOptions);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate void GetSystemInfo(
                ref SpDi.Win32.Kernel32.SYSTEM_INFO Info);
        }
    }
}
