#pragma once

#define KUSER_SHARED_DATA (DWORD)0x7FFE0000
#define P_KUSER_SHARED_DATA_COOKIE reinterpret_cast<DWORD *>(KUSER_SHARED_DATA + 0x0330)

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 ) 

typedef LONG KPRIORITY;

//Macro to convert dumb 64-types into a DWORD without triggereing C4302 or C4311 (also works on 32-bit sized pointers)
#define MDWD(p) (DWORD)((ULONG_PTR)p & 0xFFFFFFFF)

#ifndef NT_FAIL
#define NT_FAIL(status) (status < 0)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(status) (status >= 0)
#endif

#define STATUS_SUCCESS 0
#define STATUS_NOT_FOUND 0xC0000225
#define STATUS_SXS_IDENTITIES_DIFFERENT 0xC015001D

//macro to avoid compiler and shellcode related alignment issues (unlikely but just to be sure)
#define ALIGN_64 __declspec(align(8))
#define ALIGN_86 __declspec(align(4))

#ifdef _WIN64
#define ALIGN ALIGN_64
#else
#define ALIGN ALIGN_86
#endif



typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation = 0,
	ObjectTypeInformation = 2
} OBJECT_INFORMATION_CLASS;

typedef enum _LDR_HOT_PATCH_STATE
{
	LdrHotPatchBaseImage = 0,
	LdrHotPatchNotApplied = 1,
	LdrHotPatchAppliedReverse = 2,
	LdrHotPatchAppliedForward = 3,
	LdrHotPatchFailedToPatch = 4,
	LdrHotPatchStateMax = 5
} LDR_HOT_PATCH_STATE, * PLDR_HOT_PATCH_STATE;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
	PVOID       Object;
	ULONG_PTR   UniqueProcessId;
	ULONG_PTR   HandleValue;
	ULONG       GrantedAccess;
	USHORT      CreatorBackTraceIndex;
	USHORT      ObjectTypeIndex;
	ULONG       HandleAttributes;
	ULONG       Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
	ULONG_PTR   NumberOfHandles;
	ULONG_PTR   Reserved;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

typedef enum _LDR_DDAG_STATE : int
{
	LdrModulesMerged = -5,
	LdrModulesInitError = -4,
	LdrModulesSnapError = -3,
	LdrModulesUnloaded = -2,
	LdrModulesUnloading = -1,
	LdrModulesPlaceHolder = 0,
	LdrModulesMapping = 1,
	LdrModulesMapped = 2,
	LdrModulesWaitingForDependencies = 3,
	LdrModulesSnapping = 4,
	LdrModulesSnapped = 5,
	LdrModulesCondensed = 6,
	LdrModulesReadyToInit = 7,
	LdrModulesInitializing = 8,
	LdrModulesReadyToRun = 9
} LDR_DDAG_STATE, * PLDR_DDAG_STATE;

typedef enum _LDR_DLL_LOAD_REASON : int
{
	LoadReasonUnknown = -1,
	LoadReasonStaticDependency = 0,
	LoadReasonStaticForwarderDependency = 1,
	LoadReasonDynamicForwarderDependency = 2,
	LoadReasonDelayloadDependency = 3,
	LoadReasonDynamicLoad = 4,
	LoadReasonAsImageLoad = 5,
	LoadReasonAsDataLoad = 6,
	LoadReasonEnclavePrimary = 7,
	LoadReasonEnclaveDependency = 8,
	LoadReasonPatchImage = 9
} LDR_DLL_LOAD_REASON, * PLDR_DLL_LOAD_REASON;

typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation = 0,
	ProcessQuotaLimits = 1,
	ProcessIoCounters = 2,
	ProcessVmCounters = 3,
	ProcessTimes = 4,
	ProcessBasePriority = 5,
	ProcessRaisePriority = 6,
	ProcessDebugPort = 7,
	ProcessExceptionPort = 8,
	ProcessAccessToken = 9,
	ProcessLdrInformation = 10,
	ProcessLdtSize = 11,
	ProcessDefaultHardErrorMode = 12,
	ProcessIoPortHandlers = 13,
	ProcessPooledUsageAndLimits = 14,
	ProcessWorkingSetWatch = 15,
	ProcessUserModeIOPL = 16,
	ProcessEnableAlignmentFaultFixup = 17,
	ProcessPriorityClass = 18,
	ProcessWx86Information = 19,
	ProcessHandleCount = 20,
	ProcessAffinityMask = 21,
	ProcessPriorityBoost = 22,
	ProcessDeviceMap = 23,
	ProcessSessionInformation = 24,
	ProcessForegroundInformation = 25,
	ProcessWow64Information = 26,
	ProcessImageFileName = 27,
	ProcessLUIDDeviceMapsEnabled = 28,
	ProcessBreakOnTermination = 29,
	ProcessDebugObjectHandle = 30,
	ProcessDebugFlags = 31,
	ProcessHandleTracing = 32,
	ProcessIoPriority = 33,
	ProcessExecuteFlags = 34,
	ProcessTlsInformation = 35,
	ProcessCookie = 36,
	ProcessImageInformation = 37,
	ProcessCycleTime = 38,
	ProcessPagePriority = 39,
	ProcessInstrumentationCallback = 40, // that's what we need
	ProcessThreadStackAllocation = 41,
	ProcessWorkingSetWatchEx = 42,
	ProcessImageFileNameWin32 = 43,
	ProcessImageFileMapping = 44,
	ProcessAffinityUpdateMode = 45,
	ProcessMemoryAllocationMode = 46,
	ProcessGroupInformation = 47,
	ProcessTokenVirtualizationEnabled = 48,
	ProcessConsoleHostProcess = 49,
	ProcessWindowInformation = 50,
	ProcessHandleInformation = 51,
	MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef  enum  _THREADINFOCLASS
{
	ThreadBasicInformation,  //  q:  THREAD_BASIC_INFORMATION
	ThreadTimes,  //  q:  KERNEL_USER_TIMES
	ThreadPriority,  //  s:  KPRIORITY
	ThreadBasePriority,  //  s:  LONG
	ThreadAffinityMask,  //  s:  KAFFINITY
	ThreadImpersonationToken,  //  s:  HANDLE
	ThreadDescriptorTableEntry,  //  q:  DESCRIPTOR_TABLE_ENTRY  (or  WOW64_DESCRIPTOR_TABLE_ENTRY)
	ThreadEnableAlignmentFaultFixup,  //  s:  BOOLEAN
	ThreadEventPair,
	ThreadQuerySetWin32StartAddress,  //  q:  PVOID
	ThreadZeroTlsCell,  //  10
	ThreadPerformanceCount,  //  q:  LARGE_INTEGER
	ThreadAmILastThread,  //  q:  ULONG
	ThreadIdealProcessor,  //  s:  ULONG
	ThreadPriorityBoost,  //  qs:  ULONG
	ThreadSetTlsArrayAddress,
	ThreadIsIoPending,  //  q:  ULONG
	ThreadHideFromDebugger,  //  s:  void
	ThreadBreakOnTermination,  //  qs:  ULONG
	ThreadSwitchLegacyState,
	ThreadIsTerminated,  //  q:  ULONG  //  20
	ThreadLastSystemCall,  //  q:  THREAD_LAST_SYSCALL_INFORMATION
	ThreadIoPriority,  //  qs:  IO_PRIORITY_HINT
	ThreadCycleTime,  //  q:  THREAD_CYCLE_TIME_INFORMATION
	ThreadPagePriority,  //  q:  ULONG
	ThreadActualBasePriority,
	ThreadTebInformation,  //  q:  THREAD_TEB_INFORMATION  (requires  THREAD_GET_CONTEXT  +  THREAD_SET_CONTEXT)
	ThreadCSwitchMon,
	ThreadCSwitchPmu,
	ThreadWow64Context,  //  q:  WOW64_CONTEXT
	ThreadGroupInformation,  //  q:  GROUP_AFFINITY  //  30
	ThreadUmsInformation,  //  q:  THREAD_UMS_INFORMATION
	ThreadCounterProfiling,
	ThreadIdealProcessorEx,  //  q:  PROCESSOR_NUMBER
	ThreadCpuAccountingInformation,  //  since  WIN8
	ThreadSuspendCount,  //  since  WINBLUE
	ThreadHeterogeneousCpuPolicy,  //  q:  KHETERO_CPU_POLICY  //  since  THRESHOLD
	ThreadContainerId,  //  q:  GUID
	ThreadNameInformation,  //  qs:  THREAD_NAME_INFORMATION
	ThreadSelectedCpuSets,
	ThreadSystemThreadInformation,  //  q:  SYSTEM_THREAD_INFORMATION  //  40
	ThreadActualGroupAffinity,  //  since  THRESHOLD2
	ThreadDynamicCodePolicyInfo,
	ThreadExplicitCaseSensitivity,
	ThreadWorkOnBehalfTicket,
	ThreadSubsystemInformation,  //  q:  SUBSYSTEM_INFORMATION_TYPE  //  since  REDSTONE2
	ThreadDbgkWerReportActive,
	ThreadAttachContainer,
	MaxThreadInfoClass
}  THREADINFOCLASS;

typedef enum _WORKERFACTORYINFOCLASS
{
	WorkerFactoryTimeout, // LARGE_INTEGER
	WorkerFactoryRetryTimeout, // LARGE_INTEGER
	WorkerFactoryIdleTimeout, // s: LARGE_INTEGER
	WorkerFactoryBindingCount, // s: ULONG
	WorkerFactoryThreadMinimum, // s: ULONG
	WorkerFactoryThreadMaximum, // s: ULONG
	WorkerFactoryPaused, // ULONG or BOOLEAN
	WorkerFactoryBasicInformation, // q: WORKER_FACTORY_BASIC_INFORMATION
	WorkerFactoryAdjustThreadGoal,
	WorkerFactoryCallbackType,
	WorkerFactoryStackInformation, // 10
	WorkerFactoryThreadBasePriority, // s: ULONG
	WorkerFactoryTimeoutWaiters, // s: ULONG, since THRESHOLD
	WorkerFactoryFlags, // s: ULONG
	WorkerFactoryThreadSoftMaximum, // s: ULONG
	WorkerFactoryThreadCpuSets, // since REDSTONE5
	MaxWorkerFactoryInfoClass
} WORKERFACTORYINFOCLASS, * PWORKERFACTORYINFOCLASS;

typedef struct _LDR_SERVICE_TAG_RECORD
{
	struct _LDR_SERVICE_TAG_RECORD* Next;
	ULONG ServiceTag;
} LDR_SERVICE_TAG_RECORD, * PLDR_SERVICE_TAG_RECORD;
struct PEB;

typedef struct _ANSI_STRING
{
	USHORT	Length;
	USHORT	MaxLength;
	char* szBuffer;
} ANSI_STRING, * PANSI_STRING;

typedef struct _UNICODE_STRING
{
	WORD		Length;
	WORD		MaxLength;
	wchar_t* szBuffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef ALIGN_86 struct _UNICODE_STRING_32
{
	WORD	Length;
	WORD	MaxLength;
	DWORD	szBuffer;
} UNICODE_STRING_32, * PUNICODE_STRING_32;

typedef ALIGN_86 struct _RTL_BALANCED_NODE_32
{
	union
	{
		DWORD Children[2];
		struct
		{
			DWORD Left;
			DWORD Right;
		};
	};

	union
	{
		UCHAR Red : 1;
		UCHAR Balance : 2;
		DWORD ParentValue;
	};
} RTL_BALANCED_NODE_32, * PRTL_BALANCED_NODE_32;

typedef ALIGN_86 struct _SINGLE_LIST_ENTRY_32
{
	DWORD Next; // -> SINGLE_LIST_ENTRY_32
} SINGLE_LIST_ENTRY_32, * PSINGLE_LIST_ENTRY_32;

typedef struct _RTL_BALANCED_NODE
{
	union
	{
		struct _RTL_BALANCED_NODE* Children[2];
		struct
		{
			struct _RTL_BALANCED_NODE* Left;
			struct _RTL_BALANCED_NODE* Right;
		};
	};

	union
	{
		UCHAR Red : 1;
		UCHAR Balance : 2;
		ULONG_PTR ParentValue;
	};
} RTL_BALANCED_NODE, * PRTL_BALANCED_NODE;

typedef struct _RTL_RB_TREE
{
	RTL_BALANCED_NODE* Root;
	RTL_BALANCED_NODE* Min;
} RTL_RB_TREE, * PRTL_RB_TREE;

typedef struct _LDRP_CSLIST
{
	struct _SINGLE_LIST_ENTRY* Tail;
} LDRP_CSLIST, * PLDRP_CSLIST;

//Win10 1511
typedef struct _LDRP_PATH_SEARCH_CONTEXT_1511
{
	wchar_t* DllSearchPathOut;
	void* Unknown_0[2];
	wchar_t* OriginalFullDllName;
	void* unknown_1[7];
	ULONG64		unknown_2[4];
} LDRP_PATH_SEARCH_CONTEXT_1511, * PLDRP_PATH_SEARCH_CONTEXT_1511; //x86 size = 0x4C, x64 size = 0x78

//Win10 1507, 1607+
typedef struct _LDRP_PATH_SEARCH_CONTEXT
{
	wchar_t* DllSearchPathOut;
	void* Unknown_0[3];
	wchar_t* OriginalFullDllName;
	void* unknown_1[7];
	ULONG64		unknown_2[4];
} LDRP_PATH_SEARCH_CONTEXT, * PLDRP_PATH_SEARCH_CONTEXT; //x86 size <= 0x50, x64 size <= 0x80

typedef struct _LDRP_UNICODE_STRING_BUNDLE
{
	UNICODE_STRING	String;
	WCHAR			StaticBuffer[128];
} LDRP_UNICODE_STRING_BUNDLE, * PLDRP_UNICODE_STRING_BUNDLE;

typedef union _LDR_SEARCH_PATH
{
	BOOLEAN NoPath : 1;
	wchar_t* szSearchPath;
} LDR_SEARCH_PATH, * PLDR_SEARCH_PATH;

typedef struct _LDRP_PATH_SEARCH_CONTEXT_WIN81
{
	UINT_PTR unknown_0[3];
	wchar_t* OriginalFullDllName;
	UINT_PTR unknown_1[1];
} LDRP_PATH_SEARCH_CONTEXT_WIN81, * PLDRP_PATH_SEARCH_CONTEXT_WIN81; //x86 size = 0x14, x64 size = 0x28

typedef struct _LDRP_PATH_SEARCH_CONTEXT_WIN8
{
	ULONG_PTR Flags; //probably LDRP_LOAD_CONTEXT_FLAGS
	wchar_t* OriginalFullDllName; //can be path
	BOOLEAN		unknown2; //only low byte relevant
	ULONG_PTR	unknown3[3]; //sometimes imagebase?
} LDRP_PATH_SEARCH_CONTEXT_WIN8, * PLDRP_PATH_SEARCH_CONTEXT_WIN8;

typedef struct _LDR_DDAG_NODE_WIN8
{
	LIST_ENTRY				Modules;
	PLDR_SERVICE_TAG_RECORD	ServiceTagList;
	ULONG					LoadCount;
	ULONG					ReferenceCount;
	ULONG					DependencyCount;
	union
	{
		LDRP_CSLIST			Dependencies;
		SINGLE_LIST_ENTRY* RemovalLink;
	};
	PLDRP_CSLIST			IncomingDependencies;
	LDR_DDAG_STATE			State;
	SINGLE_LIST_ENTRY		CondenseLink;
	ULONG					PreorderNumber;
	ULONG					LowestLink;
} LDR_DDAG_NODE_WIN8, * PLDR_DDAG_NODE_WIN8;

typedef struct _LDR_DDAG_NODE_WIN81
{
	LIST_ENTRY				Modules;
	PLDR_SERVICE_TAG_RECORD	ServiceTagList;
	ULONG					LoadCount;
	ULONG					ReferenceCount;
	ULONG					DependencyCount;
	union
	{
		LDRP_CSLIST			Dependencies;
		SINGLE_LIST_ENTRY* RemovalLink;
	};
	PLDRP_CSLIST			IncomingDependencies;
	LDR_DDAG_STATE			State;
	SINGLE_LIST_ENTRY		CondenseLink;
	ULONG					PreorderNumber;
	ULONG					LowestLink;
} LDR_DDAG_NODE_WIN81, * PLDR_DDAG_NODE_WIN81;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION
{
	NTSTATUS	ExitStatus;
	PVOID		TebBaseAddress;
	CLIENT_ID	ClientId;
	KAFFINITY	AffinityMask;
	KPRIORITY	Priority;
	KPRIORITY	BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG				Length;
	HANDLE				RootDirectory;
	UNICODE_STRING* ObjectName;
	ULONG				Attributes;
	PVOID				SecurityDescriptor;
	PVOID				SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef enum _MEMORY_INFORMATION_CLASS {
	MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		NTSTATUS	Status;
		PVOID		Pointer;
	} DUMMYUNIONNAME;

	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef union _LDRP_LOAD_CONTEXT_FLAGS
{
	ULONG32 Flags;
	struct //These are very most likely wrong!
	{
		ULONG32 Redirected : 1;
		ULONG32 Static : 1;
		ULONG32 BaseNameOnly : 1;
		ULONG32 HasFullPath : 1;
		ULONG32 KnownDll : 1;
		ULONG32 SystemImage : 1;
		ULONG32 ExecutableImage : 1;
		ULONG32 AppContainerImage : 1;
		ULONG32 CallInit : 1;
		ULONG32 UserAllocated : 1;
		ULONG32 SearchOnlyFirstPathSegment : 1;
		ULONG32 RedirectedByAPISet : 1;
	};
} LDRP_LOAD_CONTEXT_FLAGS, * PLDRP_LOAD_CONTEXT_FLAGS;

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
	ULONG Version;
	ULONG Reserved;
	PVOID Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, * PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;


template <typename T>
struct _NT_TIB_T
{
	T ExceptionList;
	T StackBase;
	T StackLimit;
	T SubSystemTib;
	T FiberData;
	T ArbitraryUserPointer;
	T Self;
};

template <typename T>
struct _CLIENT_ID_T
{
	T UniqueProcess;
	T UniqueThread;
};

template <typename T>
struct _LIST_ENTRY_T
{
	T Flink;
	T Blink;
};

template <int n>
using const_int = std::integral_constant<int, n>;

template<typename T>
constexpr bool is32bit = std::is_same_v<T, uint32_t>;

template<typename T, typename T32, typename T64>
using type_32_64 = std::conditional_t<is32bit<T>, T32, T64>;

template<typename T, int v32, int v64>
constexpr int int_32_64 = std::conditional_t<is32bit<T>, const_int<v32>, const_int<v64>>::value;

template <typename T>
struct _ACTIVATION_CONTEXT_STACK_T
{
	T ActiveFrame;
	_LIST_ENTRY_T<T> FrameListCache;
	uint32_t Flags;
	uint32_t NextCookieSequenceNumber;
	uint32_t StackId;
};

typedef struct _RTL_INVERTED_FUNCTION_TABLE_ENTRY
{
	IMAGE_RUNTIME_FUNCTION_ENTRY* ExceptionDirectory;
	PVOID							ImageBase;
	ULONG							ImageSize;
	ULONG							SizeOfTable;
} RTL_INVERTED_FUNCTION_TABLE_ENTRY, * PRTL_INVERTED_FUNCTION_TABLE_ENTRY;

typedef struct _RTL_INVERTED_FUNCTION_TABLE
{
	ULONG Count;
	ULONG MaxCount;
	ULONG Epoch;
	UCHAR Overflow;
	RTL_INVERTED_FUNCTION_TABLE_ENTRY Entries[ANYSIZE_ARRAY];
} RTL_INVERTED_FUNCTION_TABLE, * PRTL_INVERTED_FUNCTION_TABLE;

template <typename T>
struct _GDI_TEB_BATCH_T
{
	uint32_t Offset;
	T HDC;
	uint32_t Buffer[310];
};

template <typename T>
struct _UNICODE_STRING_T
{
	using type = T;

	uint16_t Length;
	uint16_t MaximumLength;
	T Buffer;
};

template <typename T>
struct _TEB_T
{
	struct Specific32_1
	{
		uint8_t InstrumentationCallbackDisabled;
		uint8_t SpareBytes[23];
		uint32_t TxFsContext;
	};

	struct Specific64_1
	{
		uint32_t TxFsContext;
		uint32_t InstrumentationCallbackDisabled;
	};

	struct Specific64_2
	{
		T TlsExpansionSlots;
		T DeallocationBStore;
		T BStoreLimit;
	};

	struct Specific32_2
	{
		T TlsExpansionSlots;
	};

	_NT_TIB_T<T> NtTib;
	T EnvironmentPointer;
	_CLIENT_ID_T<T> ClientId;
	T ActiveRpcHandle;
	T ThreadLocalStoragePointer;
	T ProcessEnvironmentBlock;
	uint32_t LastErrorValue;
	uint32_t CountOfOwnedCriticalSections;
	T CsrClientThread;
	T Win32ThreadInfo;
	uint32_t User32Reserved[26];
	uint32_t UserReserved[5];
	T WOW32Reserved;
	uint32_t CurrentLocale;
	uint32_t FpSoftwareStatusRegister;
	T ReservedForDebuggerInstrumentation[16];
	T SystemReserved1[int_32_64<T, 26, 30>];
	uint8_t PlaceholderCompatibilityMode;
	uint8_t PlaceholderReserved[11];
	uint32_t ProxiedProcessId;
	_ACTIVATION_CONTEXT_STACK_T<T> ActivationStack;
	uint8_t WorkingOnBehalfTicket[8];
	uint32_t ExceptionCode;
	T ActivationContextStackPointer;
	T InstrumentationCallbackSp;
	T InstrumentationCallbackPreviousPc;
	T InstrumentationCallbackPreviousSp;
	type_32_64<T, Specific32_1, Specific64_1> spec1;
	_GDI_TEB_BATCH_T<T> GdiTebBatch;
	_CLIENT_ID_T<T> RealClientId;
	T GdiCachedProcessHandle;
	uint32_t GdiClientPID;
	uint32_t GdiClientTID;
	T GdiThreadLocalInfo;
	T Win32ClientInfo[62];
	T glDispatchTable[233];
	T glReserved1[29];
	T glReserved2;
	T glSectionInfo;
	T glSection;
	T glTable;
	T glCurrentRC;
	T glContext;
	uint32_t LastStatusValue;
	_UNICODE_STRING_T<T> StaticUnicodeString;
	wchar_t StaticUnicodeBuffer[261];
	T DeallocationStack;
	T TlsSlots[64];
	_LIST_ENTRY_T<T> TlsLinks;
	T Vdm;
	T ReservedForNtRpc;
	T DbgSsReserved[2];
	uint32_t HardErrorMode;
	T Instrumentation[int_32_64<T, 9, 11>];
	GUID ActivityId;
	T SubProcessTag;
	T PerflibData;
	T EtwTraceData;
	T WinSockData;
	uint32_t GdiBatchCount;             // TEB64 pointer
	uint32_t IdealProcessorValue;
	uint32_t GuaranteedStackBytes;
	T ReservedForPerf;
	T ReservedForOle;
	uint32_t WaitingOnLoaderLock;
	T SavedPriorityState;
	T ReservedForCodeCoverage;
	T ThreadPoolData;
	type_32_64<T, Specific32_2, Specific64_2> spec2;
	uint32_t MuiGeneration;
	uint32_t IsImpersonating;
	T NlsCache;
	T pShimData;
	uint16_t HeapVirtualAffinity;
	uint16_t LowFragHeapDataSlot;
	T CurrentTransactionHandle;
	T ActiveFrame;
	T FlsData;
	T PreferredLanguages;
	T UserPrefLanguages;
	T MergedPrefLanguages;
	uint32_t MuiImpersonation;
	uint16_t CrossTebFlags;
	union
	{
		uint16_t SameTebFlags;
		struct
		{
			uint16_t SafeThunkCall : 1;
			uint16_t InDebugPrint : 1;
			uint16_t HasFiberData : 1;
			uint16_t SkipThreadAttach : 1;
			uint16_t WerInShipAssertCode : 1;
			uint16_t RanProcessInit : 1;
			uint16_t ClonedThread : 1;
			uint16_t SuppressDebugMsg : 1;
			uint16_t DisableUserStackWalk : 1;
			uint16_t RtlExceptionAttached : 1;
			uint16_t InitialThread : 1;
			uint16_t SessionAware : 1;
			uint16_t LoadOwner : 1;
			uint16_t LoaderWorker : 1;
			uint16_t SkipLoaderInit : 1;
			uint16_t SpareSameTebBits : 1;
		};
	};
	T TxnScopeEnterCallback;
	T TxnScopeExitCallback;
	T TxnScopeContext;
	uint32_t LockCount;
	uint32_t WowTebOffset;
	T ResourceRetValue;
	T ReservedForWdf;
	uint64_t ReservedForCrt;
	GUID EffectiveContainerId;
};

using _TEB32 = _TEB_T<uint32_t>;
using _TEB64 = _TEB_T<uint64_t>;
using TEB_T = _TEB_T<uintptr_t>;


typedef enum _PROCESS_STATE_CHANGE_TYPE
{
	ProcessStateChangeSuspend = 0,
	ProcessStateChangeResume = 1,
	ProcessStateChangeMax = 2,
} PROCESS_STATE_CHANGE_TYPE, * PPROCESS_STATE_CHANGE_TYPE;

template<typename T>
struct _PEB_LDR_DATA2_T
{
	uint32_t Length;
	uint8_t Initialized;
	T SsHandle;
	_LIST_ENTRY_T<T> InLoadOrderModuleList;
	_LIST_ENTRY_T<T> InMemoryOrderModuleList;
	_LIST_ENTRY_T<T> InInitializationOrderModuleList;
	T EntryInProgress;
	uint8_t ShutdownInProgress;
	T ShutdownThreadId;
};

using _PEB_LDR_DATA2_32_T = _PEB_LDR_DATA2_T<uint32_t>;
using _PEB_LDR_DATA2_64_T = _PEB_LDR_DATA2_T<uint64_t>;

template<typename T>
struct _PEB_T
{
	static_assert(std::is_same_v<T, uint32_t> || std::is_same_v<T, uint64_t>, "T must be uint32_t or uint64_t");

	uint8_t InheritedAddressSpace;
	uint8_t ReadImageFileExecOptions;
	uint8_t BeingDebugged;
	union
	{
		uint8_t BitField;
		struct
		{
			uint8_t ImageUsesLargePages : 1;
			uint8_t IsProtectedProcess : 1;
			uint8_t IsImageDynamicallyRelocated : 1;
			uint8_t SkipPatchingUser32Forwarders : 1;
			uint8_t IsPackagedProcess : 1;
			uint8_t IsAppContainer : 1;
			uint8_t IsProtectedProcessLight : 1;
			uint8_t SpareBits : 1;
		};
	};
	T Mutant;
	T ImageBaseAddress;
	T Ldr;
	T ProcessParameters;
	T SubSystemData;
	T ProcessHeap;
	T FastPebLock;
	T AtlThunkSListPtr;
	T IFEOKey;
	union
	{
		T CrossProcessFlags;
		struct
		{
			uint32_t ProcessInJob : 1;
			uint32_t ProcessInitializing : 1;
			uint32_t ProcessUsingVEH : 1;
			uint32_t ProcessUsingVCH : 1;
			uint32_t ProcessUsingFTH : 1;
			uint32_t ReservedBits0 : 27;
		};
	};
	union
	{
		T KernelCallbackTable;
		T UserSharedInfoPtr;
	};
	uint32_t SystemReserved;
	uint32_t AtlThunkSListPtr32;
	T ApiSetMap;
	union
	{
		uint32_t TlsExpansionCounter;
		T Padding2;
	};
	T TlsBitmap;
	uint32_t TlsBitmapBits[2];
	T ReadOnlySharedMemoryBase;
	T SparePvoid0;
	T ReadOnlyStaticServerData;
	T AnsiCodePageData;
	T OemCodePageData;
	T UnicodeCaseTableData;
	uint32_t NumberOfProcessors;
	uint32_t NtGlobalFlag;
	LARGE_INTEGER CriticalSectionTimeout;
	T HeapSegmentReserve;
	T HeapSegmentCommit;
	T HeapDeCommitTotalFreeThreshold;
	T HeapDeCommitFreeBlockThreshold;
	uint32_t NumberOfHeaps;
	uint32_t MaximumNumberOfHeaps;
	T ProcessHeaps;
	T GdiSharedHandleTable;
	T ProcessStarterHelper;
	union
	{
		uint32_t GdiDCAttributeList;
		T Padding3;
	};
	T LoaderLock;
	uint32_t OSMajorVersion;
	uint32_t OSMinorVersion;
	uint16_t OSBuildNumber;
	uint16_t OSCSDVersion;
	uint32_t OSPlatformId;
	uint32_t ImageSubsystem;
	uint32_t ImageSubsystemMajorVersion;
	union
	{
		uint32_t ImageSubsystemMinorVersion;
		T Padding4;
	};
	T ActiveProcessAffinityMask;
	uint32_t GdiHandleBuffer[int_32_64<T, 34, 60>];
	T PostProcessInitRoutine;
	T TlsExpansionBitmap;
	uint32_t TlsExpansionBitmapBits[32];
	union
	{
		uint32_t SessionId;
		T Padding5;
	};
	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	T pShimData;
	T AppCompatInfo;
	_UNICODE_STRING_T<T> CSDVersion;
	T ActivationContextData;
	T ProcessAssemblyStorageMap;
	T SystemDefaultActivationContextData;
	T SystemAssemblyStorageMap;
	T MinimumStackCommit;
	T FlsCallback;
	_LIST_ENTRY_T<T> FlsListHead;
	T FlsBitmap;
	uint32_t FlsBitmapBits[4];
	uint32_t FlsHighIndex;
	T WerRegistrationData;
	T WerShipAssertPtr;
	T pUnused;
	T pImageHeaderHash;
	union
	{
		uint64_t TracingFlags;
		struct
		{
			uint32_t HeapTracingEnabled : 1;
			uint32_t CritSecTracingEnabled : 1;
			uint32_t LibLoaderTracingEnabled : 1;
			uint32_t SpareTracingBits : 29;
		};
	};
	T CsrServerReadOnlySharedMemoryBase;
};
namespace ntenum
{
	typedef enum _JOBOBJECTINFOCLASS2 {
		JobObjectBasicAccountingInformation = 1,
		JobObjectBasicLimitInformation,
		JobObjectBasicProcessIdList,
		JobObjectBasicUIRestrictions,
		JobObjectSecurityLimitInformation,  // deprecated
		JobObjectEndOfJobTimeInformation,
		JobObjectAssociateCompletionPortInformation,
		JobObjectBasicAndIoAccountingInformation,
		JobObjectExtendedLimitInformation,
		JobObjectJobSetInformation,
		JobObjectGroupInformation,
		JobObjectNotificationLimitInformation,
		JobObjectLimitViolationInformation,
		JobObjectGroupInformationEx,
		JobObjectCpuRateControlInformation,
		JobObjectCompletionFilter,
		JobObjectCompletionCounter,

		//
		//

		JobObjectFreezeInformation,
		JobObjectExtendedAccountingInformation,
		JobObjectWakeInformation,
		JobObjectBackgroundInformation,
		JobObjectSchedulingRankBiasInformation,
		JobObjectTimerVirtualizationInformation,
		JobObjectCycleTimeNotification,
		JobObjectClearEvent,
		JobObjectInterferenceInformation,
		JobObjectClearPeakJobMemoryUsed,
		JobObjectMemoryUsageInformation,
		JobObjectSharedCommit,
		JobObjectContainerId,
		JobObjectIoRateControlInformation,
		JobObjectNetRateControlInformation,
		JobObjectNotificationLimitInformation2,
		JobObjectLimitViolationInformation2,
		JobObjectCreateSilo,
		JobObjectSiloBasicInformation,
		JobObjectReserved15Information = 37,
		JobObjectReserved16Information = 38,
		JobObjectReserved17Information = 39,
		JobObjectReserved18Information = 40,
		JobObjectReserved19Information = 41,
		JobObjectReserved20Information = 42,
		JobObjectReserved21Information = 43,
		JobObjectReserved22Information = 44,
		JobObjectReserved23Information = 45,
		JobObjectReserved24Information = 46,
		JobObjectReserved25Information = 47,
		JobObjectReserved26Information = 48,
		JobObjectReserved27Information = 49,
		MaxJobObjectInfoClass
	} JOBOBJECTINFOCLASS2;

}

typedef struct _JOBOBJECT_WAKE_FILTER
{
	ULONG HighEdgeFilter;
	ULONG LowEdgeFilter;
} JOBOBJECT_WAKE_FILTER, * PJOBOBJECT_WAKE_FILTER;

// private
typedef struct _JOBOBJECT_FREEZE_INFORMATION
{
	union
	{
		ULONG Flags;
		struct
		{
			ULONG FreezeOperation : 1;
			ULONG FilterOperation : 1;
			ULONG SwapOperation : 1;
			ULONG Reserved : 29;
		};
	};
	BOOLEAN Freeze;
	BOOLEAN Swap;
	UCHAR Reserved0[2];
	JOBOBJECT_WAKE_FILTER WakeFilter;
} JOBOBJECT_FREEZE_INFORMATION, * PJOBOBJECT_FREEZE_INFORMATION;

typedef struct _TLS_ENTRY
{
	LIST_ENTRY				TlsEntryLinks;
	IMAGE_TLS_DIRECTORY		TlsDirectory;
	PVOID 					ModuleEntry; //LdrDataTableEntry
	SIZE_T					TlsIndex;
} TLS_ENTRY, * PTLS_ENTRY;

using _PEB32 = _PEB_T<uint32_t>;
using _PEB64 = _PEB_T<uint64_t>;
using PEB_T = _PEB_T<uintptr_t>;

typedef struct _PROCESS_BASIC_INFORMATION
{
	NTSTATUS	ExitStatus;
	void* pPEB;
	ULONG_PTR	AffinityMask;
	LONG		BasePriority;
	HANDLE		UniqueProcessId;
	HANDLE		InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

typedef struct {
	unsigned int  dr0_local : 1;
	unsigned int  dr0_global : 1;
	unsigned int  dr1_local : 1;
	unsigned int  dr1_global : 1;
	unsigned int  dr2_local : 1;
	unsigned int  dr2_global : 1;
	unsigned int  dr3_local : 1;
	unsigned int  dr3_global : 1;
	unsigned int  local_enabled : 1;
	unsigned int  global_enabled : 1;
	unsigned int  reserved_10 : 1;
	unsigned int  rtm : 1;
	unsigned int  reserved_12 : 1;
	unsigned int  gd : 1;
	unsigned int  reserved_14_15 : 2;
	unsigned int  dr0_break : 2;
	unsigned int  dr0_len : 2;
	unsigned int  dr1_break : 2;
	unsigned int  dr1_len : 2;
	unsigned int  dr2_break : 2;
	unsigned int  dr2_len : 2;
	unsigned int  dr3_break : 2;
	unsigned int  dr3_len : 2;
} dr7_t;