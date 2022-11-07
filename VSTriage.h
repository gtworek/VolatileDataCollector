#pragma once
#include <WinSock2.h>
#include <IPTypes.h>
#include <strsafe.h>
#include <Windows.h>
#include <wchar.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <WinDNS.h>
#include <ip2string.h>
#include <VersionHelpers.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "Secur32.lib")


#define CRASHIFNULLALLOC(x) if (NULL == (x)) {wprintf(L"FATAL ERROR. Cannot allocate memory in %hs\r\n", __func__); _exit(ERROR_NOT_ENOUGH_MEMORY);} __noop
#define ALLOCORCRASH(p,bytes) (p) = LocalAlloc(LPTR,(bytes)); CRASHIFNULLALLOC(p); __noop

#define DBGTRACE wprintf(L"> # %i             \r\n", __LINE__); __noop

#define REPORTERROR(s,x) wprintf(L"\r\nERROR. %s %i (%hs#%i)\r\n", s, x, __FILE__, __LINE__)

#define CHECKSTRINGHR(x) if (S_OK != (x)) {wprintf(L"FATAL ERROR. String operation failed in %hs\r\n", __func__); _exit(RPC_S_STRING_TOO_LONG);} __noop
#define Add2Ptr(Ptr,Inc) ((PVOID)((PUCHAR)(Ptr) + (Inc)))

typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation = 0,
	ProcessDebugPort = 7,
	ProcessWow64Information = 26,
	ProcessImageFileName = 27,
	ProcessBreakOnTermination = 29,
	ProcessSubsystemInformation = 75
} PROCESSINFOCLASS;

typedef struct _PEB_FREE_BLOCK
{
	struct _PEB_FREE_BLOCK* Next;
	ULONG Size;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING;


typedef struct _RTL_BALANCED_NODE
{
	union
	{
		struct _RTL_BALANCED_NODE* Children[2];

		struct
		{
			struct _RTL_BALANCED_NODE* Left;
			struct _RTL_BALANCED_NODE* Right;
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;

#define RTL_BALANCED_NODE_RESERVED_PARENT_MASK 3

	union
	{
		UCHAR Red : 1;
		UCHAR Balance : 2;
		ULONG_PTR ParentValue;
	} DUMMYUNIONNAME2;
} RTL_BALANCED_NODE, *PRTL_BALANCED_NODE;

typedef enum _LDR_DLL_LOAD_REASON
{
	LoadReasonStaticDependency,
	LoadReasonStaticForwarderDependency,
	LoadReasonDynamicForwarderDependency,
	LoadReasonDelayloadDependency,
	LoadReasonDynamicLoad,
	LoadReasonAsImageLoad,
	LoadReasonAsDataLoad,
	LoadReasonEnclavePrimary,
	LoadReasonEnclaveDependency,
	LoadReasonUnknown = -1
} LDR_DLL_LOAD_REASON, *PLDR_DLL_LOAD_REASON;

typedef struct _LDR_SERVICE_TAG_RECORD
{
	struct _LDR_SERVICE_TAG_RECORD* Next;
	ULONG ServiceTag;
} LDR_SERVICE_TAG_RECORD, *PLDR_SERVICE_TAG_RECORD;

typedef struct _LDRP_CSLIST
{
	PSINGLE_LIST_ENTRY Tail;
} LDRP_CSLIST, *PLDRP_CSLIST;

typedef enum _LDR_DDAG_STATE
{
	LdrModulesMerged = -5,
	LdrModulesInitError = -4,
	LdrModulesSnapError = -3,
	LdrModulesUnloaded = -2,
	LdrModulesUnloading = -1,
	LdrModulesPlaceHolder = 0,
	LdrModulesMapping,
	LdrModulesMapped,
	LdrModulesWaitingForDependencies,
	LdrModulesSnapping,
	LdrModulesSnapped,
	LdrModulesCondensed,
	LdrModulesReadyToInit,
	LdrModulesInitializing,
	LdrModulesReadyToRun,
} LDR_DDAG_STATE;

typedef struct _LDR_DDAG_NODE
{
	LIST_ENTRY Modules;
	PLDR_SERVICE_TAG_RECORD ServiceTagList;
	ULONG LoadCount;
	ULONG LoadWhileUnloadingCount;
	ULONG LowestLink;
	LDRP_CSLIST Dependencies;
	LDRP_CSLIST IncomingDependencies;
	LDR_DDAG_STATE State;
	SINGLE_LIST_ENTRY CondenseLink;
	ULONG PreorderNumber;
} LDR_DDAG_NODE, *PLDR_DDAG_NODE;

// 
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;

	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;

	union
	{
		UCHAR FlagGroup[4];
		ULONG Flags;

		struct
		{
			ULONG PackagedBinary : 1;
			ULONG MarkedForRemoval : 1;
			ULONG ImageDll : 1;
			ULONG LoadNotificationsSent : 1;
			ULONG TelemetryEntryProcessed : 1;
			ULONG ProcessStaticImport : 1;
			ULONG InLegacyLists : 1;
			ULONG InIndexes : 1;
			ULONG ShimDll : 1;
			ULONG InExceptionTable : 1;
			ULONG ReservedFlags1 : 2;
			ULONG LoadInProgress : 1;
			ULONG LoadConfigProcessed : 1;
			ULONG EntryProcessed : 1;
			ULONG ProtectDelayLoad : 1;
			ULONG ReservedFlags3 : 2;
			ULONG DontCallForThreads : 1;
			ULONG ProcessAttachCalled : 1;
			ULONG ProcessAttachFailed : 1;
			ULONG CorDeferredValidate : 1;
			ULONG CorImage : 1;
			ULONG DontRelocate : 1;
			ULONG CorILOnly : 1;
			ULONG ChpeImage : 1;
			ULONG ReservedFlags5 : 2;
			ULONG Redirected : 1;
			ULONG ReservedFlags6 : 2;
			ULONG CompatDatabaseProcessed : 1;
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;

	USHORT ObsoleteLoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
	PVOID Lock;
	PLDR_DDAG_NODE DdagNode;
	LIST_ENTRY NodeModuleLink;
	struct _LDRP_LOAD_CONTEXT* LoadContext;
	PVOID ParentDllBase;
	PVOID SwitchBackContext;
	RTL_BALANCED_NODE BaseAddressIndexNode;
	RTL_BALANCED_NODE MappingInfoIndexNode;
	ULONG_PTR OriginalBase;
	LARGE_INTEGER LoadTime;
	ULONG BaseNameHashValue;
	LDR_DLL_LOAD_REASON LoadReason;
	ULONG ImplicitPathOptions;
	ULONG ReferenceCount;
	ULONG DependentLoadFlags;
	SE_SIGNING_LEVEL SigningLevel;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;


typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef PVOID* PPVOID;

typedef struct _STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PCHAR Buffer;
} STRING;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	HANDLE Handle;
} CURDIR, *PCURDIR;

//struct below taken from the "dt nt!_RTL_USER_PROCESS_PARAMETERS"
typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	HANDLE ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;
	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;
	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;
	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
	ULONGLONG EnvironmentSize;
	ULONGLONG EnvironmentVersion;
	PVOID PackageDependencyData;
	ULONG ProcessGroupId;
	ULONG LoaderThreads;
	UNICODE_STRING RedirectionDllName;
	UNICODE_STRING HeapPartitionName;
	PULONGLONG DefaultThreadpoolCpuSetMasks;
	ULONG DefaultThreadpoolCpuSetMaskCount;
	ULONG DefaultThreadpoolThreadMaximum;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

//dt nt!_PEB plus some digging through internet. Not so important for members after ProcessParameters.
typedef struct _PEB
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	BOOLEAN SpareBool;
	HANDLE Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
	PVOID FastPebLockRoutine;
	PVOID FastPebUnlockRoutine;
	ULONG EnvironmentUpdateCount;
	PVOID KernelCallbackTable;
	ULONG SystemReserved[1];

	struct foo
	{
		ULONG ExecuteOptions : 2;
		ULONG SpareBits : 30;
	};

	PPEB_FREE_BLOCK FreeList;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID ReadOnlySharedMemoryHeap;
	PPVOID ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	LARGE_INTEGER CriticalSectionTimeout;
	SIZE_T HeapSegmentReserve;
	SIZE_T HeapSegmentCommit;
	SIZE_T HeapDeCommitTotalFreeThreshold;
	SIZE_T HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PPVOID ProcessHeaps;
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;
	PVOID LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	USHORT OSBuildNumber;
	USHORT OSCSDVersion;
	ULONG OSPlatformId;
	ULONG ImageSubsystem;
	ULONG ImageSubsystemMajorVersion;
	ULONG ImageSubsystemMinorVersion;
	ULONG_PTR ImageProcessAffinityMask;
	ULONG GdiHandleBuffer[60];
	PVOID PostProcessInitRoutine;
	PVOID TlsExpansionBitmap;
	ULONG TlsExpansionBitmapBits[32];
	ULONG SessionId;
	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	PVOID pShimData;
	PVOID AppCompatInfo;
	UNICODE_STRING CSDVersion;
	PVOID ActivationContextData;
	PVOID ProcessAssemblyStorageMap;
	PVOID SystemDefaultActivationContextData;
	PVOID SystemAssemblyStorageMap;
	SIZE_T MinimumStackCommit;
} PEB, *PPEB;

typedef struct _PROCESS_BASIC_INFORMATION
{
	PVOID Reserved1;
	PPEB PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemProcessInformation = 5,
	SystemHandleInformation = 16,
	SystemExtendedHandleInformation = 0x40,
} SYSTEM_INFORMATION_CLASS;

typedef LONG KPRIORITY;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef struct _node
{
	PWSTR data;
	struct _node* next;
	struct _node* prev;
} NODE, *PNODE;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
	PVOID Object;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG_PTR NumberOfHandles;
	ULONG_PTR Reserved;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

typedef enum _OBJECT_INFORMATION_CLASS
{
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectTypesInformation,
	ObjectHandleFlagInformation,
	ObjectSessionInformation,
	MaxObjectInfoClass
} OBJECT_INFORMATION_CLASS;

typedef UNICODE_STRING* PUNICODE_STRING;

typedef struct _OBJECT_NAME_INFORMATION
{
	UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

#define NETIOAPI_API WINAPI
#define NETIO_STATUS DWORD
#define ANY_SIZE 1

typedef struct in6_addr
{
	union
	{
		UCHAR Byte[16];
		USHORT Word[8];
	} u;
} IN6_ADDR, *PIN6_ADDR, FAR*LPIN6_ADDR;

typedef struct sockaddr_in6
{
	ADDRESS_FAMILY sin6_family; 
	USHORT sin6_port; 
	ULONG sin6_flowinfo;
	IN6_ADDR sin6_addr; 
	union
	{
		ULONG sin6_scope_id;
		SCOPE_ID sin6_scope_struct;
	};
} SOCKADDR_IN6_LH, *PSOCKADDR_IN6_LH, FAR*LPSOCKADDR_IN6_LH;

typedef SOCKADDR_IN6_LH SOCKADDR_IN6;
typedef SOCKADDR_IN6_LH* PSOCKADDR_IN6;

typedef union _SOCKADDR_INET
{
	SOCKADDR_IN Ipv4;
	SOCKADDR_IN6 Ipv6;
	ADDRESS_FAMILY si_family;
} SOCKADDR_INET, *PSOCKADDR_INET;

#define IF_MAX_PHYS_ADDRESS_LENGTH 32

typedef struct _MIB_IPNET_ROW2
{
	SOCKADDR_INET Address;
	NET_IFINDEX InterfaceIndex;
	NET_LUID InterfaceLuid;
	UCHAR PhysicalAddress[IF_MAX_PHYS_ADDRESS_LENGTH];
	ULONG PhysicalAddressLength;
	NL_NEIGHBOR_STATE State;

	union
	{
		struct
		{
			BOOLEAN IsRouter : 1;
			BOOLEAN IsUnreachable : 1;
		};

		UCHAR Flags;
	};

	union
	{
		ULONG LastReachable;
		ULONG LastUnreachable;
	} ReachabilityTime;
} MIB_IPNET_ROW2, *PMIB_IPNET_ROW2;

typedef struct _MIB_IPNET_TABLE2
{
	ULONG NumEntries;
	MIB_IPNET_ROW2 Table[ANY_SIZE];
} MIB_IPNET_TABLE2, *PMIB_IPNET_TABLE2;


typedef struct _DNS_CACHE_TABLE_
{
	struct _DNS_CACHE_TABLE_* pNext;
	PWSTR Name;
	WORD Type1;
	WORD Type2;
	WORD Type3;
} DNS_CACHE_TABLE, *PDNS_CACHE_TABLE;

typedef enum _TCP_TABLE_CLASS
{
	TCP_TABLE_BASIC_LISTENER,
	TCP_TABLE_BASIC_CONNECTIONS,
	TCP_TABLE_BASIC_ALL,
	TCP_TABLE_OWNER_PID_LISTENER,
	TCP_TABLE_OWNER_PID_CONNECTIONS,
	TCP_TABLE_OWNER_PID_ALL,
	TCP_TABLE_OWNER_MODULE_LISTENER,
	TCP_TABLE_OWNER_MODULE_CONNECTIONS,
	TCP_TABLE_OWNER_MODULE_ALL
} TCP_TABLE_CLASS, *PTCP_TABLE_CLASS;

typedef enum _UDP_TABLE_CLASS
{
	UDP_TABLE_BASIC,
	UDP_TABLE_OWNER_PID,
	UDP_TABLE_OWNER_MODULE
} UDP_TABLE_CLASS, *PUDP_TABLE_CLASS;


#define TCPIP_OWNING_MODULE_SIZE 16


typedef struct _MIB_TCPROW_OWNER_MODULE
{
	DWORD dwState;
	DWORD dwLocalAddr;
	DWORD dwLocalPort;
	DWORD dwRemoteAddr;
	DWORD dwRemotePort;
	DWORD dwOwningPid;
	LARGE_INTEGER liCreateTimestamp;
	ULONGLONG OwningModuleInfo[TCPIP_OWNING_MODULE_SIZE];
} MIB_TCPROW_OWNER_MODULE, *PMIB_TCPROW_OWNER_MODULE;

typedef struct _MIB_TCPTABLE_OWNER_MODULE
{
	DWORD dwNumEntries;
	MIB_TCPROW_OWNER_MODULE table[ANY_SIZE];
} MIB_TCPTABLE_OWNER_MODULE, *PMIB_TCPTABLE_OWNER_MODULE;

typedef struct _MIB_TCP6ROW_OWNER_MODULE
{
	UCHAR ucLocalAddr[16];
	DWORD dwLocalScopeId;
	DWORD dwLocalPort;
	UCHAR ucRemoteAddr[16];
	DWORD dwRemoteScopeId;
	DWORD dwRemotePort;
	DWORD dwState;
	DWORD dwOwningPid;
	LARGE_INTEGER liCreateTimestamp;
	ULONGLONG OwningModuleInfo[TCPIP_OWNING_MODULE_SIZE];
} MIB_TCP6ROW_OWNER_MODULE, *PMIB_TCP6ROW_OWNER_MODULE;

typedef struct _MIB_TCP6TABLE_OWNER_MODULE
{
	DWORD dwNumEntries;
	MIB_TCP6ROW_OWNER_MODULE table[ANY_SIZE];
} MIB_TCP6TABLE_OWNER_MODULE, *PMIB_TCP6TABLE_OWNER_MODULE;

typedef struct _MIB_UDPROW_OWNER_MODULE
{
	DWORD dwLocalAddr;
	DWORD dwLocalPort;
	DWORD dwOwningPid;
	LARGE_INTEGER liCreateTimestamp;

	union
	{
		struct
		{
			int SpecificPortBind : 1;
		};

		int dwFlags;
	};

	ULONGLONG OwningModuleInfo[TCPIP_OWNING_MODULE_SIZE];
} MIB_UDPROW_OWNER_MODULE, *PMIB_UDPROW_OWNER_MODULE;

typedef struct _MIB_UDPTABLE_OWNER_MODULE
{
	DWORD dwNumEntries;
	MIB_UDPROW_OWNER_MODULE table[ANY_SIZE];
} MIB_UDPTABLE_OWNER_MODULE, *PMIB_UDPTABLE_OWNER_MODULE;

typedef struct _MIB_UDP6ROW_OWNER_MODULE
{
	UCHAR ucLocalAddr[16];
	DWORD dwLocalScopeId;
	DWORD dwLocalPort;
	DWORD dwOwningPid;
	LARGE_INTEGER liCreateTimestamp;

	union
	{
		struct
		{
			int SpecificPortBind : 1;
		};

		int dwFlags;
	};

	ULONGLONG OwningModuleInfo[TCPIP_OWNING_MODULE_SIZE];
} MIB_UDP6ROW_OWNER_MODULE, *PMIB_UDP6ROW_OWNER_MODULE;

typedef struct _MIB_UDP6TABLE_OWNER_MODULE
{
	DWORD dwNumEntries;
	MIB_UDP6ROW_OWNER_MODULE table[ANY_SIZE];
} MIB_UDP6TABLE_OWNER_MODULE, *PMIB_UDP6TABLE_OWNER_MODULE;

typedef enum
{
	NameUnknown = 0,
	NameFullyQualifiedDN = 1,
	NameSamCompatible = 2,
	NameDisplay = 3,
	NameUniqueId = 6,
	NameCanonical = 7,
	NameUserPrincipal = 8,
	NameCanonicalEx = 9,
	NameServicePrincipal = 10,
	NameDnsDomain = 12,
	NameGivenName = 13,
	NameSurname = 14
} EXTENDED_NAME_FORMAT, *PEXTENDED_NAME_FORMAT;


#define LIVE_SYSTEM_DUMP 0x161

typedef union _SYSDBG_LIVEDUMP_CONTROL_FLAGS
{
	struct
	{
		ULONG UseDumpStorageStack : 1;
		ULONG CompressMemoryPagesData : 1;
		ULONG IncludeUserSpaceMemoryPages : 1;
		ULONG Reserved : 29;
	};

	ULONG AsUlong;
} SYSDBG_LIVEDUMP_CONTROL_FLAGS;

typedef union _SYSDBG_LIVEDUMP_CONTROL_ADDPAGES
{
	struct
	{
		ULONG HypervisorPages : 1;
		ULONG Reserved : 31;
	};

	ULONG AsUlong;
} SYSDBG_LIVEDUMP_CONTROL_ADDPAGES;

typedef struct _SYSDBG_LIVEDUMP_CONTROL
{
	ULONG Version;
	ULONG BugCheckCode;
	ULONG_PTR BugCheckParam1;
	ULONG_PTR BugCheckParam2;
	ULONG_PTR BugCheckParam3;
	ULONG_PTR BugCheckParam4;
	HANDLE DumpFileHandle;
	HANDLE CancelEventHandle;
	SYSDBG_LIVEDUMP_CONTROL_FLAGS Flags;
	SYSDBG_LIVEDUMP_CONTROL_ADDPAGES AddPagesControl;
} SYSDBG_LIVEDUMP_CONTROL, *PSYSDBG_LIVEDUMP_CONTROL;


typedef enum _SYSDBG_COMMAND
{
	SysDbgGetLiveKernelDump = 37
} SYSDBG_COMMAND, *PSYSDBG_COMMAND;


NTSTATUS
NTAPI
RtlGetVersion(
	PRTL_OSVERSIONINFOW lpVersionInformation
);

BOOLEAN
GetUserNameExW(
	EXTENDED_NAME_FORMAT NameFormat,
	LPWSTR lpNameBuffer,
	PULONG nSize
);

__kernel_entry
NTSTATUS
NTAPI
NtQueryInformationProcess(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength OPTIONAL
);

__kernel_entry
NTSYSCALLAPI
NTSTATUS
NTAPI
NtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);

NTSTATUS
NTAPI
NtQueryObject(
	HANDLE Handle,
	OBJECT_INFORMATION_CLASS ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
);

NETIO_STATUS
NETIOAPI_API
GetIpNetTable2(
	ADDRESS_FAMILY Family,
	PMIB_IPNET_TABLE2* Table
);

PCWSTR
WSAAPI
InetNtopW(
	INT Family,
	const VOID* pAddr,
	PWSTR pStringBuf,
	size_t StringBufSize
);


VOID
NETIOAPI_API
FreeMibTable(
	PVOID Memory
);

ULONG
WINAPI
GetAdaptersAddresses(
	ULONG Family,
	ULONG Flags,
	PVOID Reserved,
	PIP_ADAPTER_ADDRESSES AdapterAddresses,
	PULONG SizePointer
);

DWORD
WINAPI
DnsGetCacheDataTableEx(
	ULONG64 Flags,
	DNS_CACHE_TABLE** ppTable
);

BOOL
WINAPI
DnsGetCacheDataTable(
	DNS_CACHE_TABLE** ppTable
);

DWORD
WINAPI
GetExtendedTcpTable(
	PVOID pTcpTable,
	PDWORD pdwSize,
	BOOL bOrder,
	ULONG ulAf,
	TCP_TABLE_CLASS TableClass,
	ULONG Reserved
);

DWORD
WINAPI
GetExtendedUdpTable(
	PVOID pUdpTable,
	PDWORD pdwSize,
	BOOL bOrder,
	ULONG ulAf,
	UDP_TABLE_CLASS TableClass,
	ULONG Reserved
);


__kernel_entry
NTSYSCALLAPI
NTSTATUS
NTAPI
NtSystemDebugControl(
	SYSDBG_COMMAND Command,
	PVOID InputBuffer,
	ULONG InputBufferLength,
	PVOID OutputBuffer,
	ULONG OutputBufferLength,
	PULONG ReturnLength
);


VOID SortUniqueMultilineWchar(PWSTR pwszStringToSort, PWSTR* pwszSortedString);
VOID ResizeWcharBufIfNeeded(PWSTR* pwszBuffer, size_t* pstBufferSizeBytes);
VOID ShrinkWcharBuffer(PWSTR* pwszBuffer);
VOID AddCheckHeader(PWSTR pwszBuffer, size_t stBufferSizeBytes, PWSTR pwszHeaderContent, BOOL bStartWithCRLF);
VOID InsertAtOutputTail(PWSTR x);
VOID EnableAllPrivileges(void);
PWSTR GetCurrentTimeZ(void);
PWSTR SystemTimeToISO8601(SYSTEMTIME stTime);
BOOL KernelDump(PWSTR pwszDumpName);
PWSTR HNM_Output(void);
PWSTR TLV_Output(void);
PWSTR SET_Output(void);
PWSTR TLM_Output(void);
PWSTR TLM2_Output(void);
PWSTR DRV_Output(void);
PWSTR CUSR_Output(void);
PWSTR HND_Output(void);
PWSTR ARPA_Output(void);
PWSTR ICOA_Output(void);
PWSTR ICOD_Output(void);
PWSTR NANO_Output(void);
PWSTR KLS_Output(void);


static const WCHAR BOM = 0xfeff;

#define SIZE_16MB (16*1024*1024)
#define SIZE_1MB (1024*1024)
#define SIZE_1KB 1024
#define MAX_PRIVILEGE_NAME_LEN 64
#define USERNAME_LENGTH 512
#define DOMAINNAME_LENGTH 512
#define TICKS_IN_MS 10000
#define INITIAL_PROCESS_COUNT 1024
#define ISO_TIME_LEN 22
#define ISO_TIME_FORMAT_W L"%04i-%02i-%02iT%02i:%02i:%02iZ"
#define CERT_SHA1_HASH_LENGTH 20
#define THREAD_TIMEOUT_MS 1000
#define INET6_ADDRSTRLEN 65
#define DNS_GET_ALL_CACHE_ENTRIES 0x1
#define DNS_TYPE_ZERO 0x0000
#define BLANKS_TO_WRITE 40
#define TICKS_PER_MS 10000

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)    // ntsubauth
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
