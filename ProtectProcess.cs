using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text;
/*
Author: Elm0D, Twitter: @Elm0D
 * 
 * Usage:
   ProtectProcess.Protect();
 * 
Based on 
 * https://gist.github.com/subTee/9808dd07493601cb30fc97bdbe832f71
*/
class ProtectProcess
    {
        public static void Protect()
        {
            IntPtr hProcess = GetCurrentProcess();
            // Read the DACL
            var dacl = GetProcessSecurityDescriptor(hProcess);
            // Remove ACE
            ThreadACE();
            for (int i = 0; i < dacl.DiscretionaryAcl.Count; i++)
            {
                dacl.DiscretionaryAcl.RemoveAce(i);
            }
            SetProcessSecurityDescriptor(hProcess, dacl);
            Chink();
            Choke();
        }
        private static void Choke()
        {
            Process[] processlist = Process.GetProcesses();
            int nProcessID = Process.GetCurrentProcess().Id;

            foreach (Process theprocess in processlist)
            {
                if (theprocess.ProcessName.Equals(Process.GetCurrentProcess().ProcessName) && theprocess.Id != nProcessID)
                {
                    IntPtr procPtr = OpenProcess(ProcessAccessRights.WRITE_DAC, false, theprocess.Id);
                    IntPtr hProcess = GetCurrentProcess();
                    var dacl = GetProcessSecurityDescriptor(hProcess);
                    SetProcessSecurityDescriptor(procPtr, dacl);
                    CloseHandle(procPtr);
                    procPtr = OpenProcess(ProcessAccessRights.PROCESS_TERMINATE, false, theprocess.Id);
                    TerminateProcess(procPtr, 1);
                }
            }
        }
        private static void Chink()
        {
            Process[] processlist = Process.GetProcesses();
            int nProcessID = Process.GetCurrentProcess().Id;

            foreach (Process theprocess in processlist)
            {
                if (theprocess.ProcessName.Equals(Process.GetCurrentProcess().ProcessName) && theprocess.Id != nProcessID)
                {
                    foreach (ProcessThread td in theprocess.Threads)
                    {
                        if (theprocess.ProcessName.Equals(Process.GetCurrentProcess().ProcessName) && theprocess.Id != nProcessID)
                        {
                            IntPtr tdPtr = OpenThread(ThreadAccess.TERMINATE, false, (uint)td.Id);
                        }
                    }
                }
            }
        }
        private static void ThreadACE()
        {
            Process[] processlist = Process.GetProcesses();
            int nProcessID = Process.GetCurrentProcess().Id;
            foreach (Process theprocess in processlist)
            {
                if (theprocess.ProcessName.Equals(Process.GetCurrentProcess().ProcessName) && theprocess.Id == nProcessID)
                {
                    foreach (ProcessThread td in theprocess.Threads)
                    {
                        if (theprocess.ProcessName.Equals(Process.GetCurrentProcess().ProcessName) && theprocess.Id == nProcessID)
                        {
                            IntPtr tdPtr = OpenThread(ThreadAccess.THREAD_ALL_ACCESS, false, (uint)td.Id);
                            var tdacl = GetProcessSecurityDescriptor(tdPtr);
                            for (int i = 0; i < tdacl.DiscretionaryAcl.Count; i++)
                            {
                                tdacl.DiscretionaryAcl.RemoveAce(i);
                            }
                            SetProcessSecurityDescriptor(tdPtr, tdacl);
                        }
                    }
                }
            }
        }
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetKernelObjectSecurity(IntPtr Handle, int securityInformation, [Out] byte[] pSecurityDescriptor,
        uint nLength, out uint lpnLengthNeeded);
        private static RawSecurityDescriptor GetProcessSecurityDescriptor(IntPtr processHandle)
        {
            const int DACL_SECURITY_INFORMATION = 0x00000004;
            byte[] psd = new byte[0];
            uint bufSizeNeeded;
            // Call with 0 size to obtain the actual size needed in bufSizeNeeded
            GetKernelObjectSecurity(processHandle, DACL_SECURITY_INFORMATION, psd, 0, out bufSizeNeeded);
            if (bufSizeNeeded < 0 || bufSizeNeeded > short.MaxValue)
                throw new Win32Exception();
            // Allocate the required bytes and obtain the DACL
            if (!GetKernelObjectSecurity(processHandle, DACL_SECURITY_INFORMATION,
            psd = new byte[bufSizeNeeded], bufSizeNeeded, out bufSizeNeeded))
                throw new Win32Exception();
            // Use the RawSecurityDescriptor class from System.Security.AccessControl to parse the bytes:
            return new RawSecurityDescriptor(psd, 0);
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetKernelObjectSecurity(IntPtr Handle, int securityInformation, [In] byte[] pSecurityDescriptor);
        private static void SetProcessSecurityDescriptor(IntPtr processHandle, RawSecurityDescriptor dacl)
        {
            const int DACL_SECURITY_INFORMATION = 0x00000004;
            byte[] rawsd = new byte[dacl.BinaryLength];
            dacl.GetBinaryForm(rawsd, 0);
            if (!SetKernelObjectSecurity(processHandle, DACL_SECURITY_INFORMATION, rawsd))
                throw new Win32Exception();
        }
        [DllImport("Kernel32.dll", CharSet = CharSet.Auto)]
        private static extern int TerminateThread(IntPtr hThread);
        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
        [Flags]
        private enum ThreadAccess : int
        {
            TERMINATE = (0x0001),
            SUSPEND_RESUME = (0x0002),
            GET_CONTEXT = (0x0008),
            SET_CONTEXT = (0x0010),
            SET_INFORMATION = (0x0020),
            QUERY_INFORMATION = (0x0040),
            SET_THREAD_TOKEN = (0x0080),
            IMPERSONATE = (0x0100),
            DIRECT_IMPERSONATION = (0x0200),
            SYNCHRONIZE = (0x00100000),
            STANDARD_RIGHTS_REQUIRED = 0x000f0000,
            THREAD_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3FF)
        }
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(
             ProcessAccessRights processAccess,
             bool bInheritHandle,
             int processId
        );
        private static IntPtr OpenProcess(Process proc, ProcessAccessRights flags)
        {
            return OpenProcess(flags, false, proc.Id);
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hHandle);
        [Flags]
        private enum ProcessAccessRights
        {
            PROCESS_CREATE_PROCESS = 0x0080, //  Required to create a process.
            PROCESS_CREATE_THREAD = 0x0002, //  Required to create a thread.
            PROCESS_DUP_HANDLE = 0x0040, // Required to duplicate a handle using DuplicateHandle.
            PROCESS_QUERY_INFORMATION = 0x0400, //  Required to retrieve certain information about a process, such as its token, exit code, and priority class (see OpenProcessToken, GetExitCodeProcess, GetPriorityClass, and IsProcessInJob).
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000, //  Required to retrieve certain information about a process (see QueryFullProcessImageName). A handle that has the PROCESS_QUERY_INFORMATION access right is automatically granted PROCESS_QUERY_LIMITED_INFORMATION. Windows Server 2003 and Windows XP/2000:  This access right is not supported.
            PROCESS_SET_INFORMATION = 0x0200, //    Required to set certain information about a process, such as its priority class (see SetPriorityClass).
            PROCESS_SET_QUOTA = 0x0100, //  Required to set memory limits using SetProcessWorkingSetSize.
            PROCESS_SUSPEND_RESUME = 0x0800, // Required to suspend or resume a process.
            PROCESS_TERMINATE = 0x0001, //  Required to terminate a process using TerminateProcess.
            PROCESS_VM_OPERATION = 0x0008, //   Required to perform an operation on the address space of a process (see VirtualProtectEx and WriteProcessMemory).
            PROCESS_VM_READ = 0x0010, //    Required to read memory in a process using ReadProcessMemory.
            PROCESS_VM_WRITE = 0x0020, //   Required to write to memory in a process using WriteProcessMemory.
            DELETE = 0x00010000, // Required to delete the object.
            READ_CONTROL = 0x00020000, //   Required to read information in the security descriptor for the object, not including the information in the SACL. To read or write the SACL, you must request the ACCESS_SYSTEM_SECURITY access right. For more information, see SACL Access Right.
            SYNCHRONIZE = 0x00100000, //    The right to use the object for synchronization. This enables a thread to wait until the object is in the signaled state.
            WRITE_DAC = 0x00040000, //  Required to modify the DACL in the security descriptor for the object.
            WRITE_OWNER = 0x00080000, //    Required to change the owner in the security descriptor for the object.
            STANDARD_RIGHTS_REQUIRED = 0x000f0000,
            PROCESS_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFF),//    All possible access rights for a process object.
        }
    }

