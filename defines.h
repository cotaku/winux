typedef struct _IMAGE_DOS_HEADER		// DOS .EXE header
{      
	u16	e_magic;                     // Magic number
	u16	e_cblp;                      // u8s on last page of file
	u16	e_cp;                        // Pages in file
	u16	e_crlc;                      // Relocations
	u16	e_cparhdr;                   // Size of header in paragraphs
	u16	e_minalloc;                  // Minimum extra paragraphs needed
	u16	e_maxalloc;                  // Maximum extra paragraphs needed
	u16	e_ss;                        // Initial (relative) SS value
	u16	e_sp;                        // Initial SP value
	u16	e_csum;                      // Checksum
	u16	e_ip;                        // Initial IP value
	u16	e_cs;                        // Initial (relative) CS value
	u16	e_lfarlc;                    // File address of relocation table
	u16	e_ovno;                      // Overlay number
	u16	e_res[4];                    // Reserved u16s
	u16	e_oemid;                     // OEM identifier (for e_oeminfo)
	u16	e_oeminfo;                   // OEM information; e_oemid specific
	u16	e_res2[10];                  // Reserved u16s
	u32	e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER
{
	u16	Machine;
	u16	NumberOfSections;
	u32	TimeDateStamp;
	u32	PointerToSymbolTable;
	u32	NumberOfSymbols;
	u16	SizeOfOptionalHeader;
	u16	Characteristics;
} IMAGE_FILE_HEADER;

// Characteristics
#define IMAGE_FILE_EXECUTABLE_IMAGE	0x0002  // File is executable  (i.e. no unresolved externel references).
#define IMAGE_FILE_DLL				0x2000  // File is a DLL.

typedef struct _IMAGE_DATA_DIRECTORY 
{
	u32	VirtualAddress;
	u32	Size;
} IMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES	16

typedef struct _IMAGE_OPTIONAL_HEADER 
{
	// Standard fields.
	u16	Magic;
	u8	MajorLinkerVersion;
	u8	MinorLinkerVersion;
	u32	SizeOfCode;
	u32	SizeOfInitializedData;
	u32	SizeOfUninitializedData;
	u32	AddressOfEntryPoint;
	u32	BaseOfCode;
	u32	BaseOfData;
	// NT additional fields.
	u32	ImageBase;
	u32	SectionAlignment;
	u32	FileAlignment;
	u16	MajorOperatingSystemVersion;
	u16	MinorOperatingSystemVersion;
	u16	MajorImageVersion;
	u16	MinorImageVersion;
	u16	MajorSubsystemVersion;
	u16	MinorSubsystemVersion;
	u32	Win32VersionValue;
	u32	SizeOfImage;
	u32	SizeOfHeaders;
	u32	CheckSum;
	u16	Subsystem;
	u16	DllCharacteristics;
	u32	SizeOfStackReserve;
	u32	SizeOfStackCommit;
	u32	SizeOfHeapReserve;
	u32	SizeOfHeapCommit;
	u32	LoaderFlags;
	u32	NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY	DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_NT_HEADERS
{
	u32	Signature;
	IMAGE_FILE_HEADER	FileHeader;
	IMAGE_OPTIONAL_HEADER	OptionalHeader;
} IMAGE_NT_HEADER;

#define IMAGE_SIZEOF_SHORT_NAME 8

typedef struct _IMAGE_SECTION_HEADER
{
	u8	Name[IMAGE_SIZEOF_SHORT_NAME];
	union
	{
		u32	PhysicalAddress;
		u32	VirtualSize;
	} Misc;
	u32	VirtualAddress;
	u32	SizeOfRawData;
	u32	PointerToRawData;
	u32	PointerToRelocations;
	u32	PointerToLinenumbers;
	u16	NumberOfRelocations;
	u16	NumberOfLinenumbers;
	u32	Characteristics;
} IMAGE_SECTION_HEADER;

#define IMAGE_SCN_CNT_CODE					0x00000020	// Section contains code.
#define IMAGE_SCN_CNT_INITIALIZED_DATA		0x00000040	// Section contains initialized data.
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA	0x00000080	// Section contains uninitialized data.
#define IMAGE_SCN_MEM_DISCARDABLE			0x02000000	// Section can be discarded.
#define IMAGE_SCN_MEM_EXECUTE				0x20000000	// Section is executable.
#define IMAGE_SCN_MEM_READ					0x40000000	// Section is readable.
#define IMAGE_SCN_MEM_WRITE					0x80000000	// Section is writeable.

#define PAGE_SHIFT	12
#define PAGE_SIZE	(1UL << PAGE_SHIFT)
#define PAGESTART(x)	((x) & ~(unsigned long)(PAGE_SIZE-1))
#define PAGEOFFSET(x)	((x) & (PAGE_SIZE-1))
#define PAGEALIGN(x)	(((x) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

typedef struct _IMAGE_IMPORT_DESCRIPTOR 
{
	union 
	{
		u32	Characteristics;            // 0 for terminating null import descriptor
		u32	OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
	} DUMMYUNIONNAME;
	u32	TimeDateStamp;                  // 0 if not bound,
                                        // -1 if bound, and real date\time stamp in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                        // O.W. date/time stamp of DLL bound to (Old BIND)
	u32	ForwarderChain;                 // -1 if no forwarders
	u32	Name;
	u32	FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_IMPORT_BY_NAME
{
	u16	Hint;
	u8	Name[1];
} IMAGE_IMPORT_BY_NAME;

typedef struct _IMAGE_THUNK_DATA32 
{
	union 
	{
		u32 ForwarderString;      // PBYTE 
		u32 Function;             // Pu32
		u32 Ordinal;
		u32 AddressOfData;        // PIMAGE_IMPORT_BY_NAME
	} u1;
} IMAGE_THUNK_DATA;

typedef struct _IMAGE_EXPORT_DIRECTORY
{
	u32	Characteristics;
	u32	TimeDateStamp;
	u16	MajorVersion;
	u16	MinorVersion;
	u32	Name;
	u32	Base;
	u32	NumberOfFunctions;
	u32	NumberOfNames;
	u32	AddressOfFunctions;     // RVA from base of image
	u32	AddressOfNames;         // RVA from base of image
	u32	AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY;

#define MAX_DLL_PATH_LEN 128
