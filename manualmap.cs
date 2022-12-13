using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;

namespace ManualMapApi
{
    public class imports
    {
        public const uint PAGE_NOACCESS = 0x1;
        public const uint PAGE_READONLY = 0x2;
        public const uint PAGE_READWRITE = 0x4;
        public const uint PAGE_WRITECOPY = 0x8;
        public const uint PAGE_EXECUTE = 0x10;
        public const uint PAGE_EXECUTE_READ = 0x20;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;
        public const uint PAGE_EXECUTE_WRITECOPY = 0x80;
        public const uint PAGE_GUARD = 0x100;
        public const uint PAGE_NOCACHE = 0x200;
        public const uint PAGE_WRITECOMBINE = 0x400;

        public const uint MEM_COMMIT = 0x1000;
        public const uint MEM_RESERVE = 0x2000;
        public const uint MEM_DECOMMIT = 0x4000;
        public const uint MEM_RELEASE = 0x8000;

        public const uint PROCESS_WM_READ = 0x0010;
        public const uint PROCESS_ALL_ACCESS = 0x1F0FFF;

        public const int EXCEPTION_CONTINUE_EXECUTION = -1;
        public const int EXCEPTION_CONTINUE_SEARCH = 0;

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public int BaseAddress;
            public int AllocationBase;
            public uint AllocationProtect;
            public int RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [DllImport("kernel32.dll")]
        public static extern int OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern int ReadProcessMemory(int hProcess, int lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        public static extern int WriteProcessMemory(int hProcess, int lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern int VirtualProtectEx(int hProcess, int lpBaseAddress, int dwSize, uint new_protect, ref uint lpOldProtect);

        [DllImport("kernel32.dll")]
        public static extern int VirtualQueryEx(int hProcess, int lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll")]
        public static extern int VirtualAllocEx(int hProcess, int lpAddress, int size, uint allocation_type, uint protect);

        [DllImport("kernel32.dll")]
        public static extern int VirtualFreeEx(int hProcess, int lpAddress, int size, uint allocation_type);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern int GetModuleHandle(string lpModuleName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern int GetProcAddress(int hModule, string procName);

        [DllImport("kernel32.dll")]
        public static extern uint GetLastError();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(int hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetExitCodeProcess(int hProcess, out uint lpExitCode);

        [DllImport("kernel32.dll")]
        public static extern int CreateRemoteThread(int hProcess, int lpThreadAttributes, uint dwStackSize, int lpStartAddress, int lpParameter, uint dwCreationFlags, out int lpThreadId);
    }

    public class MapInject
    {

        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        };

        const int IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;

        public struct IMAGE_OPTIONAL_HEADER // IMAGE_OPTIONAL_HEADER32
        {
            //
            // Standard fields.
            //
            public UInt16 Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt32 BaseOfData;

            //
            // NT additional fields.
            //
            public UInt32 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt32 SizeOfStackReserve;
            public UInt32 SizeOfStackCommit;
            public UInt32 SizeOfHeapReserve;
            public UInt32 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;
            // DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = DataDirectory[16]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;
        };

        public static IMAGE_OPTIONAL_HEADER toImageOptionalHeader(byte[] byteArray, int offset)
        {
            IMAGE_OPTIONAL_HEADER x;
            x.Magic = BitConverter.ToUInt16(byteArray, offset + 0);
            x.MajorLinkerVersion = (byte)BitConverter.ToChar(byteArray, offset + 2);
            x.MinorLinkerVersion = (byte)BitConverter.ToChar(byteArray, offset + 3);
            x.SizeOfCode = BitConverter.ToUInt32(byteArray, offset + 4);
            x.SizeOfInitializedData = BitConverter.ToUInt32(byteArray, offset + 8);
            x.SizeOfUninitializedData = BitConverter.ToUInt32(byteArray, offset + 12);
            x.AddressOfEntryPoint = BitConverter.ToUInt32(byteArray, offset + 16);
            x.BaseOfCode = BitConverter.ToUInt32(byteArray, offset + 20);
            x.BaseOfData = BitConverter.ToUInt32(byteArray, offset + 24);

            x.ImageBase = BitConverter.ToUInt32(byteArray, offset + 28);
            x.SectionAlignment = BitConverter.ToUInt32(byteArray, offset + 32);
            x.FileAlignment = BitConverter.ToUInt32(byteArray, offset + 36);
            x.MajorOperatingSystemVersion = BitConverter.ToUInt16(byteArray, offset + 40);
            x.MinorOperatingSystemVersion = BitConverter.ToUInt16(byteArray, offset + 42);
            x.MajorImageVersion = BitConverter.ToUInt16(byteArray, offset + 44);
            x.MinorImageVersion = BitConverter.ToUInt16(byteArray, offset + 46);
            x.MajorSubsystemVersion = BitConverter.ToUInt16(byteArray, offset + 48);
            x.MinorSubsystemVersion = BitConverter.ToUInt16(byteArray, offset + 50);
            x.Win32VersionValue = BitConverter.ToUInt32(byteArray, offset + 52);
            x.SizeOfImage = BitConverter.ToUInt32(byteArray, offset + 56);
            x.SizeOfHeaders = BitConverter.ToUInt32(byteArray, offset + 60);
            x.CheckSum = BitConverter.ToUInt32(byteArray, offset + 64);
            x.Subsystem = BitConverter.ToUInt16(byteArray, offset + 68);
            x.DllCharacteristics = BitConverter.ToUInt16(byteArray, offset + 70);
            x.SizeOfStackReserve = BitConverter.ToUInt32(byteArray, offset + 72);
            x.SizeOfStackCommit = BitConverter.ToUInt32(byteArray, offset + 76);
            x.SizeOfHeapReserve = BitConverter.ToUInt32(byteArray, offset + 80);
            x.SizeOfHeapCommit = BitConverter.ToUInt32(byteArray, offset + 84);
            x.LoaderFlags = BitConverter.ToUInt32(byteArray, offset + 88);
            x.NumberOfRvaAndSizes = BitConverter.ToUInt32(byteArray, offset + 92);

            x.DataDirectory = new IMAGE_DATA_DIRECTORY[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
            for (int i = 0; i < 10; i++)
            {
                IMAGE_DATA_DIRECTORY d;
                d.VirtualAddress = BitConverter.ToUInt32(byteArray, offset + (96 + (i * 8)) + 0);
                d.Size = BitConverter.ToUInt32(byteArray, offset + (96 + (i * 8)) + 4);
                x.DataDirectory[i] = d;
            }

            return x;
        }


        public struct IMAGE_FILE_HEADER
        {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        };

        public static IMAGE_FILE_HEADER toImageFileHeader(byte[] byteArray, int offset)
        {
            IMAGE_FILE_HEADER x;
            x.Machine = BitConverter.ToUInt16(byteArray, offset + 0);
            x.NumberOfSections = BitConverter.ToUInt16(byteArray, offset + 2);
            x.TimeDateStamp = BitConverter.ToUInt32(byteArray, offset + 4);
            x.PointerToSymbolTable = BitConverter.ToUInt32(byteArray, offset + 8);
            x.NumberOfSymbols = BitConverter.ToUInt32(byteArray, offset + 12);
            x.SizeOfOptionalHeader = BitConverter.ToUInt16(byteArray, offset + 16);
            x.Characteristics = BitConverter.ToUInt16(byteArray, offset + 18);
            return x;
        }

        public struct IMAGE_DOS_HEADER
        {
            public UInt16 e_magic;                     // Magic number
            public UInt16 e_cblp;                      // Bytes on last page of file
            public UInt16 e_cp;                        // Pages in file
            public UInt16 e_crlc;                      // Relocations
            public UInt16 e_cparhdr;                   // Size of header in paragraphs
            public UInt16 e_minalloc;                  // Minimum extra paragraphs needed
            public UInt16 e_maxalloc;                  // Maximum extra paragraphs needed
            public UInt16 e_ss;                        // Initial (relative) SS value
            public UInt16 e_sp;                        // Initial SP value
            public UInt16 e_csum;                      // Checksum
            public UInt16 e_ip;                        // Initial IP value
            public UInt16 e_cs;                        // Initial (relative) CS value
            public UInt16 e_lfarlc;                    // File address of relocation table
            public UInt16 e_ovno;                      // Overlay number
            public UInt16[] e_res;                     // Reserved words [4]                   
            public UInt16 e_oemid;                     // OEM identifier (for e_oeminfo)
            public UInt16 e_oeminfo;                   // OEM information; e_oemid specific
            public UInt16[] e_res2;                    // Reserved words [10]
            public UInt32 e_lfanew;                    // LONG // File address of new exe header
        };

        public static IMAGE_DOS_HEADER toImageDosHeader(byte[] byteArray, int offset)
        {
            IMAGE_DOS_HEADER x;
            x.e_magic = BitConverter.ToUInt16(byteArray, offset + 0);
            x.e_cblp = BitConverter.ToUInt16(byteArray, offset + 2);
            x.e_cp = BitConverter.ToUInt16(byteArray, offset + 4);
            x.e_crlc = BitConverter.ToUInt16(byteArray, offset + 6);
            x.e_cparhdr = BitConverter.ToUInt16(byteArray, offset + 8);
            x.e_minalloc = BitConverter.ToUInt16(byteArray, offset + 10);
            x.e_maxalloc = BitConverter.ToUInt16(byteArray, offset + 12);
            x.e_ss = BitConverter.ToUInt16(byteArray, offset + 14);
            x.e_sp = BitConverter.ToUInt16(byteArray, offset + 16);
            x.e_csum = BitConverter.ToUInt16(byteArray, offset + 18);
            x.e_ip = BitConverter.ToUInt16(byteArray, offset + 20);
            x.e_cs = BitConverter.ToUInt16(byteArray, offset + 22);
            x.e_lfarlc = BitConverter.ToUInt16(byteArray, offset + 24);
            x.e_ovno = BitConverter.ToUInt16(byteArray, offset + 26);
            x.e_res = new UInt16[4];
            x.e_res[0] = BitConverter.ToUInt16(byteArray, offset + 28);
            x.e_res[1] = BitConverter.ToUInt16(byteArray, offset + 30);
            x.e_res[2] = BitConverter.ToUInt16(byteArray, offset + 32);
            x.e_res[3] = BitConverter.ToUInt16(byteArray, offset + 34);
            x.e_oemid = BitConverter.ToUInt16(byteArray, offset + 36);
            x.e_oeminfo = BitConverter.ToUInt16(byteArray, offset + 38);
            x.e_res2 = new UInt16[10];
            x.e_res2[0] = BitConverter.ToUInt16(byteArray, offset + 40);
            x.e_res2[1] = BitConverter.ToUInt16(byteArray, offset + 42);
            x.e_res2[2] = BitConverter.ToUInt16(byteArray, offset + 44);
            x.e_res2[3] = BitConverter.ToUInt16(byteArray, offset + 46);
            x.e_res2[4] = BitConverter.ToUInt16(byteArray, offset + 48);
            x.e_res2[5] = BitConverter.ToUInt16(byteArray, offset + 50);
            x.e_res2[6] = BitConverter.ToUInt16(byteArray, offset + 52);
            x.e_res2[7] = BitConverter.ToUInt16(byteArray, offset + 54);
            x.e_res2[8] = BitConverter.ToUInt16(byteArray, offset + 56);
            x.e_res2[9] = BitConverter.ToUInt16(byteArray, offset + 58);
            x.e_lfanew = BitConverter.ToUInt32(byteArray, offset + 60);
            return x;
        }

        public struct IMAGE_NT_HEADERS // IMAGE_NT_HEADERS32
        {
            public UInt32 Signature; // + 0
            public IMAGE_FILE_HEADER FileHeader; // + 4
            public IMAGE_OPTIONAL_HEADER OptionalHeader; // + 24
        };

        public static IMAGE_NT_HEADERS toImageNtHeaders(byte[] byteArray, int offset)
        {
            IMAGE_NT_HEADERS ntHeaders;
            ntHeaders.Signature = BitConverter.ToUInt32(byteArray, offset + 0);
            ntHeaders.FileHeader = toImageFileHeader(byteArray, offset + 4);
            ntHeaders.OptionalHeader = toImageOptionalHeader(byteArray, offset + 24);
            return ntHeaders;
        }


        public struct MANUAL_MAPPING_DATA
        {
            public int pLoadLibraryA;
            public int pGetProcAddress;
            public int pbase;
            public int hMod;
        };

        public struct IMAGE_SECTION_HEADER // size of struct = 0x28
        {
            public byte[] Name; // [IMAGE_SIZEOF_SHORT_NAME] = [8]
            public UInt32 PhysicalAddressOrVirtualSize;
            /*union {
                    DWORD   PhysicalAddress; // +0x8
                    DWORD   VirtualSize; // +0x8
            } Misc; // This is one or the other becauase it is a union
            */
            public UInt32 VirtualAddress; // +0xC
            public UInt32 SizeOfRawData; // +0x10
            public UInt32 PointerToRawData; // +0x14
            public UInt32 PointerToRelocations; // +0x18
            public UInt32 PointerToLinenumbers; // +0x1C
            public UInt16 NumberOfRelocations; // +0x20
            public UInt16 NumberOfLinenumbers; // +0x22
            public UInt32 Characteristics; // +0x24
        }


        public static IMAGE_SECTION_HEADER toImageSectionHeader(byte[] byteArray, int offset)
        {
            IMAGE_SECTION_HEADER sectionHeader;
            sectionHeader.Name = new byte[8];
            for (int i = 0; i < 8; i++)
            {
                sectionHeader.Name[i] = (byte)BitConverter.ToChar(byteArray, offset + i);
            }
            sectionHeader.PhysicalAddressOrVirtualSize = BitConverter.ToUInt32(byteArray, offset + 8);
            sectionHeader.VirtualAddress = BitConverter.ToUInt32(byteArray, offset + 12);
            sectionHeader.SizeOfRawData = BitConverter.ToUInt32(byteArray, offset + 16);
            sectionHeader.PointerToRawData = BitConverter.ToUInt32(byteArray, offset + 20);
            sectionHeader.PointerToRelocations = BitConverter.ToUInt32(byteArray, offset + 24);
            sectionHeader.PointerToLinenumbers = BitConverter.ToUInt32(byteArray, offset + 28);
            sectionHeader.NumberOfRelocations = BitConverter.ToUInt16(byteArray, offset + 32);
            sectionHeader.NumberOfLinenumbers = BitConverter.ToUInt16(byteArray, offset + 36);
            sectionHeader.Characteristics = BitConverter.ToUInt32(byteArray, offset + 40);
            return sectionHeader;
        }


        const ushort IMAGE_FILE_MACHINE_I386 = 0x014c;  // Intel 386.
        const ushort CURRENT_ARCH = IMAGE_FILE_MACHINE_I386;

        const uint STATUS_PENDING = 0x00000103;
        const uint STILL_ACTIVE = STATUS_PENDING;

        public static byte[] makePayload()
        {
            return new byte[] {
                0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x60, 0x83, 0x7D, 0x08, 0x00, 0x75, 0x0F, 0x8B, 0x45, 0x08, 0xC7,
                0x40, 0x0C, 0x40, 0x40, 0x40, 0x00, 0xE9, 0x75, 0x02, 0x00, 0x00, 0x8B, 0x4D, 0x08, 0x8B, 0x51,
                0x08, 0x89, 0x55, 0xFC, 0x8B, 0x45, 0xFC, 0x8B, 0x48, 0x3C, 0x8B, 0x55, 0xFC, 0x8D, 0x44, 0x0A,
                0x18, 0x89, 0x45, 0xF4, 0x8B, 0x4D, 0x08, 0x8B, 0x11, 0x89, 0x55, 0xC4, 0x8B, 0x45, 0x08, 0x8B,
                0x48, 0x04, 0x89, 0x4D, 0xD0, 0x8B, 0x55, 0xF4, 0x8B, 0x45, 0xFC, 0x03, 0x42, 0x10, 0x89, 0x45,
                0xA4, 0x8B, 0x4D, 0xF4, 0x8B, 0x55, 0xFC, 0x2B, 0x51, 0x1C, 0x89, 0x55, 0xD8, 0x0F, 0x84, 0xC3,
                0x00, 0x00, 0x00, 0xB8, 0x08, 0x00, 0x00, 0x00, 0x6B, 0xC8, 0x05, 0x8B, 0x55, 0xF4, 0x83, 0x7C,
                0x0A, 0x64, 0x00, 0x75, 0x0F, 0x8B, 0x45, 0x08, 0xC7, 0x40, 0x0C, 0x60, 0x60, 0x60, 0x00, 0xE9,
                0x0C, 0x02, 0x00, 0x00, 0xB9, 0x08, 0x00, 0x00, 0x00, 0x6B, 0xD1, 0x05, 0x8B, 0x45, 0xF4, 0x8B,
                0x4D, 0xFC, 0x03, 0x4C, 0x10, 0x60, 0x89, 0x4D, 0xF0, 0x8B, 0x55, 0xF0, 0x83, 0x3A, 0x00, 0x0F,
                0x84, 0x81, 0x00, 0x00, 0x00, 0x8B, 0x45, 0xF0, 0x8B, 0x48, 0x04, 0x83, 0xE9, 0x08, 0xD1, 0xE9,
                0x89, 0x4D, 0xC8, 0x8B, 0x55, 0xF0, 0x83, 0xC2, 0x08, 0x89, 0x55, 0xE0, 0xC7, 0x45, 0xDC, 0x00,
                0x00, 0x00, 0x00, 0xEB, 0x12, 0x8B, 0x45, 0xDC, 0x83, 0xC0, 0x01, 0x89, 0x45, 0xDC, 0x8B, 0x4D,
                0xE0, 0x83, 0xC1, 0x02, 0x89, 0x4D, 0xE0, 0x8B, 0x55, 0xDC, 0x3B, 0x55, 0xC8, 0x74, 0x36, 0x8B,
                0x45, 0xE0, 0x0F, 0xB7, 0x08, 0xC1, 0xF9, 0x0C, 0x83, 0xF9, 0x03, 0x75, 0x26, 0x8B, 0x55, 0xF0,
                0x8B, 0x45, 0xFC, 0x03, 0x02, 0x8B, 0x4D, 0xE0, 0x0F, 0xB7, 0x11, 0x81, 0xE2, 0xFF, 0x0F, 0x00,
                0x00, 0x03, 0xC2, 0x89, 0x45, 0xD4, 0x8B, 0x45, 0xD4, 0x8B, 0x08, 0x03, 0x4D, 0xD8, 0x8B, 0x55,
                0xD4, 0x89, 0x0A, 0xEB, 0xB0, 0x8B, 0x45, 0xF0, 0x8B, 0x4D, 0xF0, 0x03, 0x48, 0x04, 0x89, 0x4D,
                0xF0, 0xE9, 0x73, 0xFF, 0xFF, 0xFF, 0xBA, 0x08, 0x00, 0x00, 0x00, 0xC1, 0xE2, 0x00, 0x8B, 0x45,
                0xF4, 0x83, 0x7C, 0x10, 0x64, 0x00, 0x0F, 0x84, 0xDC, 0x00, 0x00, 0x00, 0xB9, 0x08, 0x00, 0x00,
                0x00, 0xC1, 0xE1, 0x00, 0x8B, 0x55, 0xF4, 0x8B, 0x45, 0xFC, 0x03, 0x44, 0x0A, 0x60, 0x89, 0x45,
                0xEC, 0x8B, 0x4D, 0xEC, 0x83, 0x79, 0x0C, 0x00, 0x0F, 0x84, 0xBA, 0x00, 0x00, 0x00, 0x8B, 0x55,
                0xEC, 0x8B, 0x45, 0xFC, 0x03, 0x42, 0x0C, 0x89, 0x45, 0xC0, 0x8B, 0x4D, 0xC4, 0x89, 0x4D, 0xBC,
                0x8B, 0x55, 0xC0, 0x52, 0xFF, 0x55, 0xBC, 0x89, 0x45, 0xCC, 0x8B, 0x45, 0xEC, 0x8B, 0x4D, 0xFC,
                0x03, 0x08, 0x89, 0x4D, 0xF8, 0x8B, 0x55, 0xEC, 0x8B, 0x45, 0xFC, 0x03, 0x42, 0x10, 0x89, 0x45,
                0xE8, 0x83, 0x7D, 0xF8, 0x00, 0x75, 0x06, 0x8B, 0x4D, 0xE8, 0x89, 0x4D, 0xF8, 0xEB, 0x12, 0x8B,
                0x55, 0xF8, 0x83, 0xC2, 0x04, 0x89, 0x55, 0xF8, 0x8B, 0x45, 0xE8, 0x83, 0xC0, 0x04, 0x89, 0x45,
                0xE8, 0x8B, 0x4D, 0xF8, 0x83, 0x39, 0x00, 0x74, 0x51, 0x8B, 0x55, 0xF8, 0x8B, 0x02, 0x25, 0x00,
                0x00, 0x00, 0x80, 0x74, 0x1F, 0x8B, 0x4D, 0xD0, 0x89, 0x4D, 0xB8, 0x8B, 0x55, 0xF8, 0x8B, 0x02,
                0x25, 0xFF, 0xFF, 0x00, 0x00, 0x50, 0x8B, 0x4D, 0xCC, 0x51, 0xFF, 0x55, 0xB8, 0x8B, 0x55, 0xE8,
                0x89, 0x02, 0xEB, 0x24, 0x8B, 0x45, 0xF8, 0x8B, 0x4D, 0xFC, 0x03, 0x08, 0x89, 0x4D, 0xB4, 0x8B,
                0x55, 0xD0, 0x89, 0x55, 0xB0, 0x8B, 0x45, 0xB4, 0x83, 0xC0, 0x02, 0x50, 0x8B, 0x4D, 0xCC, 0x51,
                0xFF, 0x55, 0xB0, 0x8B, 0x55, 0xE8, 0x89, 0x02, 0xEB, 0x95, 0x8B, 0x45, 0xEC, 0x83, 0xC0, 0x14,
                0x89, 0x45, 0xEC, 0xE9, 0x39, 0xFF, 0xFF, 0xFF, 0xB9, 0x08, 0x00, 0x00, 0x00, 0x6B, 0xD1, 0x09,
                0x8B, 0x45, 0xF4, 0x83, 0x7C, 0x10, 0x64, 0x00, 0x74, 0x4C, 0xB9, 0x08, 0x00, 0x00, 0x00, 0x6B,
                0xD1, 0x09, 0x8B, 0x45, 0xF4, 0x8B, 0x4D, 0xFC, 0x03, 0x4C, 0x10, 0x60, 0x89, 0x4D, 0xAC, 0x8B,
                0x55, 0xAC, 0x8B, 0x42, 0x0C, 0x89, 0x45, 0xE4, 0xEB, 0x09, 0x8B, 0x4D, 0xE4, 0x83, 0xC1, 0x04,
                0x89, 0x4D, 0xE4, 0x83, 0x7D, 0xE4, 0x00, 0x74, 0x1D, 0x8B, 0x55, 0xE4, 0x83, 0x3A, 0x00, 0x74,
                0x15, 0x8B, 0x45, 0xE4, 0x8B, 0x08, 0x89, 0x4D, 0xA8, 0x6A, 0x00, 0x6A, 0x01, 0x8B, 0x55, 0xFC,
                0x52, 0xFF, 0x55, 0xA8, 0xEB, 0xD4, 0x8B, 0x45, 0xA4, 0x89, 0x45, 0xA0, 0x6A, 0x00, 0x6A, 0x01,
                0x8B, 0x4D, 0xFC, 0x51, 0xFF, 0x55, 0xA0, 0x8B, 0x55, 0x08, 0x8B, 0x45, 0xFC, 0x89, 0x42, 0x0C,
                0x8B, 0xE5, 0x5D, 0xC2, 0x04, 0x00
            };
        }


        public static bool ManualMap(Process proc, string filepath)
        {
            int handle = imports.OpenProcess(imports.PROCESS_ALL_ACCESS, false, proc.Id);

            if (handle == 0)
            {
                throw new Exception("Could not open process");
            }

            byte[] pSrcData = File.ReadAllBytes(filepath);

            IMAGE_NT_HEADERS pOldNtHeader;
            IMAGE_OPTIONAL_HEADER pOldOptHeader;
            IMAGE_FILE_HEADER pOldFileHeader;

            var imageDosHeader = toImageDosHeader(pSrcData, 0);

            if (imageDosHeader.e_magic != 0x5A4D) // "MZ"
            {
                throw new Exception("Invalid file type");
            }

            pOldNtHeader = toImageNtHeaders(pSrcData, (int)imageDosHeader.e_lfanew);
            pOldOptHeader = pOldNtHeader.OptionalHeader;
            pOldFileHeader = pOldNtHeader.FileHeader;

            if (pOldFileHeader.Machine != CURRENT_ARCH)
            {
                throw new Exception("Invalid platform");
            }

            var pShellcode = imports.VirtualAllocEx(handle, 0, 0x1000, imports.MEM_COMMIT | imports.MEM_RESERVE, imports.PAGE_EXECUTE_READWRITE);
            var pTargetBase = imports.VirtualAllocEx(handle, 0, (int)pOldOptHeader.SizeOfImage, imports.MEM_COMMIT | imports.MEM_RESERVE, imports.PAGE_EXECUTE_READWRITE);
            
            if (pTargetBase == 0 || pShellcode == 0)
            {
                throw new Exception("Target process memory allocation failed (ex) [Error Code: " + imports.GetLastError() + "]");
            }

            MANUAL_MAPPING_DATA data;
            data.pLoadLibraryA = imports.GetProcAddress(imports.GetModuleHandle("KERNEL32.dll"), "LoadLibraryA");
            data.pGetProcAddress = imports.GetProcAddress(imports.GetModuleHandle("KERNEL32.dll"), "GetProcAddress");
            data.pbase = pTargetBase;
            data.hMod = 0;

            int nBytes = 0;

            // only first 0x1000 byes for the header
            if (imports.WriteProcessMemory(handle, pTargetBase, pSrcData, 0x1000, ref nBytes) == 0) 
            {
                throw new Exception("Can't write file header [Error Code: " + imports.GetLastError() + "]");
            }

            /*
            #define FIELD_OFFSET(type, field)    ((LONG)(LONG_PTR)&(((type *)0)->field))
            #define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
               ((ULONG_PTR)(ntheader) +                                            \
                FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \ // OFFSET to ->OptionalHeader = 24
                ((ntheader))->FileHeader.SizeOfOptionalHeader   \
               ))
            */
            var pOldNtHeaderAt = (int)imageDosHeader.e_lfanew;
            var pSectionHeaderAt = pOldNtHeaderAt + 24 + pOldNtHeader.FileHeader.SizeOfOptionalHeader;

            // IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
            for (uint i = 0; i != pOldFileHeader.NumberOfSections; ++i, pSectionHeaderAt += 0x28)
            {
                IMAGE_SECTION_HEADER pSectionHeader = toImageSectionHeader(pSrcData, pSectionHeaderAt);
                if (pSectionHeader.SizeOfRawData != 0)
                {
                    byte[] bytes = new byte[pSectionHeader.SizeOfRawData];
                    for (int j = 0; j < (int)pSectionHeader.SizeOfRawData; j++)
                    {
                        bytes[j] = pSrcData[pSectionHeader.PointerToRawData + j];
                    }

                    if (imports.WriteProcessMemory(handle, pTargetBase + (int)pSectionHeader.VirtualAddress, bytes, bytes.Length, ref nBytes) == 0)
                    {
                        throw new Exception("Can't map sections [Error Code: " + imports.GetLastError() + "]");
                    }
                }
            }

            //Mapping params
            int MappingDataAlloc = imports.VirtualAllocEx(handle, 0, 16, imports.MEM_COMMIT, imports.PAGE_READWRITE);
            if (MappingDataAlloc == 0)
            {
                throw new Exception("Target process mapping allocation failed (ex) [Error Code: " + imports.GetLastError() + "]");
            }

            imports.WriteProcessMemory(handle, MappingDataAlloc + 0, BitConverter.GetBytes(data.pLoadLibraryA), 4, ref nBytes);
            imports.WriteProcessMemory(handle, MappingDataAlloc + 4, BitConverter.GetBytes(data.pGetProcAddress), 4, ref nBytes);
            imports.WriteProcessMemory(handle, MappingDataAlloc + 8, BitConverter.GetBytes(data.pbase), 4, ref nBytes);
            imports.WriteProcessMemory(handle, MappingDataAlloc + 12, BitConverter.GetBytes(data.hMod), 4, ref nBytes);

            //Shell code
            if (pShellcode == 0)
            {
                throw new Exception("Memory shellcode allocation failed (ex) [Error Code: " + imports.GetLastError() + "]");
            }

            var payload = makePayload();

            if (imports.WriteProcessMemory(handle, pShellcode, payload, payload.Length, ref nBytes) == 0)
            {
                throw new Exception("Can't write shellcode [Error Code: " + imports.GetLastError() + "]");
            }

            int thId = 0;
            var hThread = imports.CreateRemoteThread(handle, 0, 0, pShellcode, MappingDataAlloc, 0, out thId);
            if (hThread == 0 || thId == 0)
            {
                throw new Exception("Thread creation failed [Error Code: " + imports.GetLastError() + "]");
            }

            imports.CloseHandle(hThread);
            //MessageBox.Show("Thread created at: " + pShellcode.ToString("X8") + ", waiting for return...");

            
            int hCheck = 0;

            while (hCheck == 0)
            {
                uint exitcode = 0;
                imports.GetExitCodeProcess(handle, out exitcode);
                if (exitcode != STILL_ACTIVE)
                {
                    throw new Exception("Process crashed, exit code: " + exitcode);
                }

                MANUAL_MAPPING_DATA dataChecked;

                byte[] readBytes = new byte[16];
                if (imports.ReadProcessMemory(handle, MappingDataAlloc, readBytes, 16, ref nBytes) == 0)
                {
                    throw new Exception("Failed to read process memory");
                }
                dataChecked.pLoadLibraryA = BitConverter.ToInt32(readBytes, 0);
                dataChecked.pGetProcAddress = BitConverter.ToInt32(readBytes, 4);
                dataChecked.pbase = BitConverter.ToInt32(readBytes, 8);
                dataChecked.hMod = BitConverter.ToInt32(readBytes, 12);
                hCheck = dataChecked.hMod;

                if (hCheck == /*(HINSTANCE)*/0x404040)
                {
                    throw new Exception("Wrong mapping ptr");
                }
                else if (hCheck == /*(HINSTANCE)*/0x606060)
                {
                    throw new Exception("Wrong directory base relocation");
                }

                Thread.Sleep(10);
            }


            //CLEAR PE HEAD
            byte[] emptyBuffer = new byte[0x1000];
            Array.Clear(emptyBuffer, 0, emptyBuffer.Length);

            
            if (imports.WriteProcessMemory(handle, pTargetBase, emptyBuffer, 0x1000, ref nBytes) == 0)
            {
                throw new Exception("Failed to erase file header(s)");
            }

            byte[] emptyBuffer2 = new byte[1024 * 1024];
            Array.Clear(emptyBuffer2, 0, emptyBuffer2.Length);

            pSectionHeaderAt = pOldNtHeaderAt + 24 + pOldNtHeader.FileHeader.SizeOfOptionalHeader;

            // IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
            for (uint i = 0; i != pOldFileHeader.NumberOfSections; ++i, pSectionHeaderAt += 0x28)
            {
                IMAGE_SECTION_HEADER pSectionHeader = toImageSectionHeader(pSrcData, pSectionHeaderAt);
                if (pSectionHeader.SizeOfRawData != 0)
                {
                    var headerName = "";
                    byte[] buffer = new byte[16];

                    imports.ReadProcessMemory(handle, pSectionHeaderAt, buffer, 16, ref nBytes);

                    for (int j = 0; j < 16; j++)
                    {
                        if (buffer[j] < 0x20 || buffer[j] >= 0x7F)
                            break;

                        headerName += (char)buffer[j];
                    }

                    if (headerName == ".pdata" || headerName == ".rsrc" || headerName == ".reloc")
                    {
                        if (imports.WriteProcessMemory(handle, pTargetBase + (int)pSectionHeader.VirtualAddress, emptyBuffer2, (int)pSectionHeader.SizeOfRawData, ref nBytes) == 0)
                        {
                            throw new Exception("Can't clear section " + headerName + " [Error code: " + imports.GetLastError() + "]");
                        }
                    }
                }
            }

            return true;
        }
    }
}
