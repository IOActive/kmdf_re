
/*
In KMDF, the first parameter into the pfnWdfCallbacks is the WdfDriverGlobals object (goes in RCX), so when we say:

NTSTATUS pfnWdfDriverCreate(PDRIVER_OBJECT DriverObject, PCUNICODE_STRING RegistryPath, PVOID DriverAttributes, PWDF_DRIVER_CONFIG DriverConfig, PVOID WdfDriver);

WdfDriverGlobals goes in RCX 
DriverObject goes in RDX
RegistryPath goes in R8
and so on


This doesn't apply to Evt*Routines like EvtIoDeviceControl.
*/

typedef enum _MAJOR_FUNCTIONS {
	 DispatchCreate,
	 DispatchCreateNamedPipe,
	 DispatchCLose,
	 DispatchRead,
	 DispatchWrite,
	 DispatchQueryInformation,
	 DispatchSetInformation,
	 DispatchQueryEA,
	 DispatchSetEA,
	 DispatchFlushBuffers,
	 DispatchQueryVolumeInformation,
	 DispatchSetVolumeInformation,
	 DispatchDirectoryControl,
	 DispatchFileSystemControl,
	 DispatchDeviceIOControl,
	 DispatchInternalDeviceControl,
	 DispatchShutdown,
	 DispatchLockControl,
	 DispatchCleanup,
	 DispatchCreateMailslot,
	 DispatchQuerySecurity,
	 DispatchSetSecurity,
	 DispatchPower,
	 DispatchSystemControl,
	 DispatchDeviceChange,
	 DispatchQueryQuota,
	 DispatchSetQuota,
	 DispatchPNP,
} MAJOR_FUNCTIONS;

typedef struct _DRIVER_OBJECT
{
     SHORT Type;
     SHORT Size;
     PVOID DeviceObject;
     ULONG Flags;
     PVOID DriverStart;
     ULONG DriverSize;
     PVOID DriverSection;
     PVOID DriverExtension;
     UNICODE_STRING DriverName;
     PUNICODE_STRING HardwareDatabase;
     PVOID FastIoDispatch;
     PVOID DriverInit;
     PVOID DriverStartIo;
     PVOID DriverUnload;
	 PVOID DispatchCreate;
	 PVOID DispatchCreateNamedPipe;
	 PVOID DispatchClose;
	 PVOID DispatchRead;
	 PVOID DispatchWrite;
	 PVOID DispatchQueryInformation;
	 PVOID DispatchSetInformation;
	 PVOID DispatchQueryEA;
	 PVOID DispatchSetEA;
	 PVOID DispatchFlushBuffers;
	 PVOID DispatchQueryVolumeInformation;
	 PVOID DispatchSetVolumeInformation;
	 PVOID DispatchDirectoryControl;
	 PVOID DispatchFileSystemControl;
	 PVOID DispatchDeviceIOControl;
	 PVOID DispatchInternalDeviceControl;
	 PVOID DispatchShutdown;
	 PVOID DispatchLockControl;
	 PVOID DispatchCleanup;
	 PVOID DispatchCreateMailslot;
	 PVOID DispatchQuerySecurity;
	 PVOID DispatchSetSecurity;
	 PVOID DispatchPower;
	 PVOID DispatchSystemControl;
	 PVOID DispatchDeviceChange;
	 PVOID DispatchQueryQuota;
	 PVOID DispatchSetQuota;
	 PVOID DispatchPNP;
} DRIVER_OBJECT, *PDRIVER_OBJECT;

typedef struct _IO_STACK_LOCATION {
		UCHAR MajorFunction;
		UCHAR MinorFunction;
		UCHAR Flags;
		UCHAR Control;
		PVOID OutputBufferLength;
		PVOID InputBufferLength;
		DWORD IOControlCode;
		PVOID Type3InputBuffer;
		PVOID DeviceObject;
		PVOID FileObject;
		PVOID CompletionRoutine;
		PVOID Context;
	} IO_STACK_LOCATION, *PIO_STACK_LOCATION;

typedef enum  { 
  DevicePropertyDeviceDescription            = 0x0,
  DevicePropertyHardwareID                   = 0x1,
  DevicePropertyCompatibleIDs                = 0x2,
  DevicePropertyBootConfiguration            = 0x3,
  DevicePropertyBootConfigurationTranslated  = 0x4,
  DevicePropertyClassName                    = 0x5,
  DevicePropertyClassGuid                    = 0x6,
  DevicePropertyDriverKeyName                = 0x7,
  DevicePropertyManufacturer                 = 0x8,
  DevicePropertyFriendlyName                 = 0x9,
  DevicePropertyLocationInformation          = 0xa,
  DevicePropertyPhysicalDeviceObjectName     = 0xb,
  DevicePropertyBusTypeGuid                  = 0xc,
  DevicePropertyLegacyBusType                = 0xd,
  DevicePropertyBusNumber                    = 0xe,
  DevicePropertyEnumeratorName               = 0xf,
  DevicePropertyAddress                      = 0x10,
  DevicePropertyUINumber                     = 0x11,
  DevicePropertyInstallState                 = 0x12,
  DevicePropertyRemovalPolicy                = 0x13,
  DevicePropertyResourceRequirements         = 0x14,
  DevicePropertyAllocatedResources           = 0x15,
  DevicePropertyContainerID                  = 0x16
} DEVICE_REGISTRY_PROPERTY;

typedef struct _WDF_VERSION {
    UINT  Major;
    UINT  Minor;
    UINT   Build;
} WDF_VERSION;
	
typedef struct _WDF_BIND_INFO {
	ULONG              Size;
	PWCHAR             Component;
	WDF_VERSION        Version;
	ULONG              FuncCount;
	PVOID 			   FuncTable;
	PVOID    Module;     // Mgmt and diagnostic use only
} WDF_BIND_INFO, * PWDF_BIND_INFO;

/*
WdfVersionBind(
    __in    PDRIVER_OBJECT DriverObject,
    __in    PUNICODE_STRING RegistryPath,
    __inout PWDF_BIND_INFO BindInfo,
    __out   PWDF_COMPONENT_GLOBALS* ComponentGlobals
    );
*/

typedef struct _WDF_PNPPOWER_EVENT_CALLBACKS {
  ULONG                                           Size;
  PVOID                         EvtDeviceD0Entry;
  PVOID EvtDeviceD0EntryPostInterruptsEnabled;
  PVOID                          EvtDeviceD0Exit;
  PVOID  EvtDeviceD0ExitPreInterruptsDisabled;
  PVOID                 EvtDevicePrepareHardware;
  PVOID                 EvtDeviceReleaseHardware;
  PVOID          EvtDeviceSelfManagedIoCleanup;
  PVOID            EvtDeviceSelfManagedIoFlush;
  PVOID             EvtDeviceSelfManagedIoInit;
  PVOID          EvtDeviceSelfManagedIoSuspend;
  PVOID          EvtDeviceSelfManagedIoRestart;
  PVOID                 EvtDeviceSurpriseRemoval;
  PVOID                     EvtDeviceQueryRemove;
  PVOID                       EvtDeviceQueryStop;
  PVOID               EvtDeviceUsageNotification;
  PVOID                  EvtDeviceRelationsQuery;
  PVOID            EvtDeviceUsageNotificationEx;
} WDF_PNPPOWER_EVENT_CALLBACKS, *PWDF_PNPPOWER_EVENT_CALLBACKS;

/*
NTSTATUS EvtWdfDevicePrepareHardware(
  WDFDEVICE Device,
  WDFCMRESLIST ResourcesRaw,
  WDFCMRESLIST ResourcesTranslated
)

The EvtDevicePrepareHardware callback function accesses the device's raw and translated hardware resources by using the ResourcesRaw and ResourcesTranslated handles that it receives. The callback function can call WdfCmResourceListGetCount and WdfCmResourceListGetDescriptor to traverse the resource lists. This callback function cannot modify the resource lists.

For more information about resource lists and the order in which the resources appear, see raw and translated hardware resources.

Typically, your driver's EvtDevicePrepareHardware callback function does the following, if necessary:

- Maps physical memory addresses to virtual addresses so the driver can access memory that is assigned to the device
- Determines the device's revision number
- Configures USB devices
- Obtains driver-defined interfaces from other drivers

Optionally, EvtDevicePrepareHardware callback function might queue a work item to complete any other time-intensive configuration tasks.
*/


// pfnWdfDeviceInitSetPnpPowerEventCallbacks

typedef struct _WDF_DRIVER_CONFIG {
  ULONG                     Size;
  PVOID EvtDriverDeviceAdd;
  PVOID     EvtDriverUnload;
  ULONG                     DriverInitFlags;
  ULONG                     DriverPoolTag;
} WDF_DRIVER_CONFIG, *PWDF_DRIVER_CONFIG;

typedef enum _WDF_SYNCHRONIZATION_SCOPE { 
  WdfSynchronizationScopeInvalid            = 0x00,
  WdfSynchronizationScopeInheritFromParent  = 0x1,
  WdfSynchronizationScopeDevice             = 0x2,
  WdfSynchronizationScopeQueue              = 0x3,
  WdfSynchronizationScopeNone               = 0x4
} WDF_SYNCHRONIZATION_SCOPE;

typedef enum _WDF_EXECUTION_LEVEL { 
  WdfExecutionLevelInvalid            = 0x00,
  WdfExecutionLevelInheritFromParent  = 0x1,
  WdfExecutionLevelPassive            = 0x2,
  WdfExecutionLevelDispatch           = 0x3
} WDF_EXECUTION_LEVEL;

typedef struct _WDF_OBJECT_CONTEXT_TYPE_INFO {
  ULONG                          Size;
  PCHAR                          ContextName;
  UINT                         ContextSize;
  PVOID UniqueType;
  PVOID    EvtDriverGetUniqueContextType;
} WDF_OBJECT_CONTEXT_TYPE_INFO, *PWDF_OBJECT_CONTEXT_TYPE_INFO;

typedef struct _WDF_OBJECT_ATTRIBUTES {
  ULONG                          Size;
  PVOID EvtCleanupCallback;
  PVOID EvtDestroyCallback;
  WDF_EXECUTION_LEVEL            ExecutionLevel;
  WDF_SYNCHRONIZATION_SCOPE      SynchronizationScope;
  HANDLE                      ParentObject;
  UINT                         ContextSizeOverride;
  PWDF_OBJECT_CONTEXT_TYPE_INFO ContextTypeInfo;
} WDF_OBJECT_ATTRIBUTES, *PWDF_OBJECT_ATTRIBUTES;


	
/*
pfnWdfObjectGetTypedContextWorker() -> receives a handle in RDX and returns a pointer into the private object context
*/

/*
NTSTATUS WdfIoQueueCreate(
  _In_      WDFDEVICE              Device,
  _In_      PWDF_IO_QUEUE_CONFIG   Config,
  _In_opt_  PWDF_OBJECT_ATTRIBUTES QueueAttributes,
  _Out_opt_ WDFQUEUE               *Queue
);

void EvtWdfIoQueueIoDeviceControl(
  WDFQUEUE Queue,
  WDFREQUEST Request,
  UINT OutputBufferLength,
  UINT InputBufferLength,
  ULONG IoControlCode
)

void EvtWdfIoQueueIoDeviceControl(
  PVOID Queue,
  PVOID Request,
  UINT OutputBufferLength,
  UINT InputBufferLength,
  ULONG IoControlCode
)


void EvtWdfIoQueueIoRead(
  WDFQUEUE Queue,
  WDFREQUEST Request,
  size_t Length
)

void EvtWdfIoQueueIoWrite(
  WDFQUEUE Queue,
  WDFREQUEST Request,
  size_t Length
)

void EvtWdfIoQueueIoInternalDeviceControl(
  WDFQUEUE Queue,
  WDFREQUEST Request,
  size_t OutputBufferLength,
  size_t InputBufferLength,
  ULONG IoControlCode
)
*/

typedef enum _WDF_DEVICE_IO_TYPE { 
  WdfDeviceIoUndefined         = 0,
  WdfDeviceIoNeither           = 1,
  WdfDeviceIoBuffered          = 2,
  WdfDeviceIoDirect            = 3,
  WdfDeviceIoBufferedOrDirect  = 4
} WDF_DEVICE_IO_TYPE, *PWDF_DEVICE_IO_TYPE;

typedef enum _WDF_IO_QUEUE_DISPATCH_TYPE { 
  WdfIoQueueDispatchInvalid     = 0,
  WdfIoQueueDispatchSequential  = 1,
  WdfIoQueueDispatchParallel    = 2,
  WdfIoQueueDispatchManual      = 3,
  WdfIoQueueDispatchMax         = 4
} WDF_IO_QUEUE_DISPATCH_TYPE;

typedef enum _WDF_TRI_STATE { 
  WdfFalse       = FALSE,
  WdfTrue        = TRUE,
  WdfUseDefault  = 2
} WDF_TRI_STATE, *PWDF_TRI_STATE;

typedef struct _WDF_IO_QUEUE_CONFIG {
  ULONG                                       Size;
  WDF_IO_QUEUE_DISPATCH_TYPE                  DispatchType;
  WDF_TRI_STATE                               PowerManaged;
  BOOLEAN                                     AllowZeroLengthRequests;
  BOOLEAN                                     DefaultQueue;
  PVOID                 EvtIoDefault;
  PVOID                    EvtIoRead;
  PVOID                   EvtIoWrite;
  PVOID          EvtIoDeviceControl;
  PVOID EvtIoInternalDeviceControl;
  PVOID                    EvtIoStop;
  PVOID                  EvtIoResume;
  PVOID       EvtIoCanceledOnQueue;
  union {
    struct {
      ULONG NumberOfPresentedRequests;
    } Parallel;
  } Settings;
  HANDLE                                   Driver;
} WDF_IO_QUEUE_CONFIG, *PWDF_IO_QUEUE_CONFIG;


/*
VOID WdfDeviceInitSetFileObjectConfig(
  _In_     PWDFDEVICE_INIT        DeviceInit,
  _In_     PWDF_FILEOBJECT_CONFIG FileObjectConfig,
  _In_opt_ PWDF_OBJECT_ATTRIBUTES FileObjectAttributes
);
*/

typedef enum _WDF_FILEOBJECT_CLASS { 
  WdfFileObjectInvalid                 = 0,
  WdfFileObjectNotRequired             = 1,
  WdfFileObjectWdfCanUseFsContext      = 2,
  WdfFileObjectWdfCanUseFsContext2     = 3,
  WdfFileObjectWdfCannotUseFsContexts  = 4,
  WdfFileObjectCanBeOptional           = 0x80000000
} WDF_FILEOBJECT_CLASS, *PWDF_FILEOBJECT_CLASS;

typedef struct _WDF_FILEOBJECT_CONFIG {
  ULONG                      Size;
  PVOID EvtDeviceFileCreate;
  PVOID         EvtFileClose;
  PVOID       EvtFileCleanup;
  WDF_TRI_STATE              AutoForwardCleanupClose;
  WDF_FILEOBJECT_CLASS       FileObjectClass;
} WDF_FILEOBJECT_CONFIG, *PWDF_FILEOBJECT_CONFIG;

/*
NTSTATUS WdfRequestRetrieveInputBuffer(
  _In_      WDFREQUEST Request,
  _In_      size_t     MinimumRequiredSize,
  _Out_     PVOID      *Buffer,
  _Out_opt_ size_t     *Length
);
*/

/*
WDF Request buffers (input and output) are hold in a structure like the follows
*/
typedef struct _BuffRequest {
	PVOID InputBuffer;
	PVOID OutputBuffer;
	DWORD64 InputBuffLen;
	DWORD64 OutputBuffLen;
} BuffRequest, *PBuffRequest;


typedef enum _WDF_REQUEST_TYPE { 
  WdfRequestTypeCreate                  = 0x0,
  WdfRequestTypeCreateNamedPipe         = 0x1,
  WdfRequestTypeClose                   = 0x2,
  WdfRequestTypeRead                    = 0x3,
  WdfRequestTypeWrite                   = 0x4,
  WdfRequestTypeQueryInformation        = 0x5,
  WdfRequestTypeSetInformation          = 0x6,
  WdfRequestTypeQueryEA                 = 0x7,
  WdfRequestTypeSetEA                   = 0x8,
  WdfRequestTypeFlushBuffers            = 0x9,
  WdfRequestTypeQueryVolumeInformation  = 0xa,
  WdfRequestTypeSetVolumeInformation    = 0xb,
  WdfRequestTypeDirectoryControl        = 0xc,
  WdfRequestTypeFileSystemControl       = 0xd,
  WdfRequestTypeDeviceControl           = 0xe,
  WdfRequestTypeDeviceControlInternal   = 0xf,
  WdfRequestTypeShutdown                = 0x10,
  WdfRequestTypeLockControl             = 0x11,
  WdfRequestTypeCleanup                 = 0x12,
  WdfRequestTypeCreateMailSlot          = 0x13,
  WdfRequestTypeQuerySecurity           = 0x14,
  WdfRequestTypeSetSecurity             = 0x15,
  WdfRequestTypePower                   = 0x16,
  WdfRequestTypeSystemControl           = 0x17,
  WdfRequestTypeDeviceChange            = 0x18,
  WdfRequestTypeQueryQuota              = 0x19,
  WdfRequestTypeSetQuota                = 0x1A,
  WdfRequestTypePnp                     = 0x1B,
  WdfRequestTypeOther                   = 0x1C,
  WdfRequestTypeUsb                     = 0x40,
  WdfRequestTypeNoFormat                = 0xFF,
  WdfRequestTypeMax                     = 0x100
} WDF_REQUEST_TYPE;


/*
WDF_REQUEST_PARAMETERS  requestParameters;
 
// Get the Request parameters
WDF_REQUEST_PARAMETERS_INIT(&requestParameters);
WdfRequestGetParameters(Request, &requestParameters);
*/

typedef struct _WDF_REQUEST_PARAMETERS {
  USHORT           Size;
  UCHAR            MinorFunction;
  WDF_REQUEST_TYPE Type;
  union {
    struct {
      PVOID     SecurityContext;
      ULONG                    Options;
      UINT64 FileAttributes;
      USHORT                   ShareAccess;
      UINT64  EaLength;
    } Create;
    struct {
      UINT                  Length;
      UINT64 Key;
      UINT64                DeviceOffset;
    } Read;
    struct {
      UINT                  Length;
      UINT64 Key;
      LONGLONG                DeviceOffset;
    } Write;
    struct {
      UINT                   OutputBufferLength;
      UINT64 InputBufferLength;
      UINT64  IoControlCode;
      PVOID                    Type3InputBuffer;
    } DeviceIoControl;
    struct {
      PVOID                   Arg1;
      PVOID                   Arg2;
      UINT64 IoControlCode;
      PVOID                   Arg4;
    } Others;
  } Parameters;
} WDF_REQUEST_PARAMETERS, *PWDF_REQUEST_PARAMETERS;



/*
NTSTATUS WdfDeviceAddQueryInterface(
  _In_ WDFDEVICE                   Device,
  _In_ PWDF_QUERY_INTERFACE_CONFIG InterfaceConfig
);
*/

typedef struct _INTERFACE {
  USHORT                 Size;
  USHORT                 Version;
  PVOID                  Context;
  PVOID   InterfaceReference;
  PVOID InterfaceDereference;
} INTERFACE, *PINTERFACE;

typedef struct _WDF_QUERY_INTERFACE_CONFIG {
  ULONG                                          Size;
  PINTERFACE                                     Interface;
  PVOID                                     GUIDInterfaceType;
  BOOLEAN                                        SendQueryToParentStack;
  PVOID  EvtDeviceProcessQueryInterfaceRequest;
  BOOLEAN                                        ImportInterface;
} WDF_QUERY_INTERFACE_CONFIG, *PWDF_QUERY_INTERFACE_CONFIG;




typedef struct _WDF_WORKITEM_CONFIG {
  ULONG            Size;
  PVOID EvtWorkItemFunc;
  BOOLEAN          AutomaticSerialization;
} WDF_WORKITEM_CONFIG, *PWDF_WORKITEM_CONFIG;

/*
NTSTATUS WdfWorkItemCreate(
  _In_  PWDF_WORKITEM_CONFIG   Config,
  _In_  PWDF_OBJECT_ATTRIBUTES Attributes,
  _Out_ WDFWORKITEM            *WorkItem
);

*/


/*
IO Targets:

A WDF driver can forward an I/O request or create and send a new request to another driver, called an I/O target.

The framework initializes a driver's local I/O target for a device when the driver calls WdfDeviceCreate. To retrieve a handle to a device's local I/O target, the driver calls WdfDeviceGetIoTarget.

NTSTATUS WdfDeviceCreate(
  PWDFDEVICE_INIT        *DeviceInit,
  PWDF_OBJECT_ATTRIBUTES DeviceAttributes,
  WDFDEVICE              *Device
);


Most drivers send requests only to their local I/O target.

To initialize a remote I/O target for a device, the driver must:
 1) Call WdfIoTargetCreate to create an I/O target object.
 2) Call WdfIoTargetOpen to open an I/O target so that the driver can send requests to it.

 
When the driver calls WdfIoTargetOpen, it typically identifies the remote I/O target by supplying a Unicode string that represents an object name. This name can identify a device, file, or device interface.

The framework sends I/O requests to the top of the driver stack that supports the object name.



NTSTATUS WdfIoTargetOpen(
  _In_ WDFIOTARGET                IoTarget,
  _In_ PWDF_IO_TARGET_OPEN_PARAMS OpenParams
);
*/


typedef enum _WDF_IO_TARGET_OPEN_TYPE { 
  WdfIoTargetOpenUndefined          = 0,
  WdfIoTargetOpenUseExistingDevice  = 1,
  WdfIoTargetOpenByName             = 2,
  WdfIoTargetOpenReopen             = 3,
  WdfIoTargetOpenLocalTargetByFile  = 4
} WDF_IO_TARGET_OPEN_TYPE;

typedef struct _WDF_IO_TARGET_OPEN_PARAMS {
  ULONG                             Size;
  WDF_IO_TARGET_OPEN_TYPE           Type;
  PVOID    EvtIoTargetQueryRemove;
  PVOID EvtIoTargetRemoveCanceled;
  PVOID EvtIoTargetRemoveComplete;
  PDEVICE_OBJECT                    TargetDeviceObject;
  PVOID                      TargetFileObject;
  UNICODE_STRING                    TargetDeviceName;
  DWORD                       DesiredAccess;
  ULONG                             ShareAccess;
  ULONG                             FileAttributes;
  ULONG                             CreateDisposition;
  ULONG                             CreateOptions;
  PVOID                             EaBuffer;
  ULONG                             EaBufferLength;
  PVOID                         AllocationSize;
  ULONG                             FileInformation;
  UNICODE_STRING                    FileName;
} WDF_IO_TARGET_OPEN_PARAMS, *PWDF_IO_TARGET_OPEN_PARAMS;

typedef struct _WDF_INTERRUPT_CONFIG {
  ULONG                           Size;
  PVOID                     SpinLock;
  WDF_TRI_STATE                   ShareVector;
  BOOLEAN                         FloatingSave;
  BOOLEAN                         AutomaticSerialization;
  PVOID           EvtInterruptIsr;
  PVOID           EvtInterruptDpc;
  PVOID        EvtInterruptEnable;
  PVOID       EvtInterruptDisable;
  PVOID      EvtInterruptWorkItem;
  PVOID InterruptRaw;
  PVOID InterruptTranslated;
  PVOID                     WaitLock;
  BOOLEAN                         PassiveHandling;
  WDF_TRI_STATE                   ReportInactiveOnPowerDown;
  BOOLEAN                         CanWakeDevice;
} WDF_INTERRUPT_CONFIG, *PWDF_INTERRUPT_CONFIG;

/*
NTSTATUS WdfInterruptCreate(
  _In_     WDFDEVICE              Device,
  _In_     PWDF_INTERRUPT_CONFIG  Configuration,
  _In_opt_ PWDF_OBJECT_ATTRIBUTES Attributes,
  _Out_    WDFINTERRUPT           *Interrupt
);
*/


/*
The WdfFdoInitSetDefaultChildListConfig method configures a bus driver's default child list.

VOID WdfFdoInitSetDefaultChildListConfig(
  _Inout_  PWDFDEVICE_INIT        DeviceInit,
  _In_     PWDF_CHILD_LIST_CONFIG Config,
  _In_opt_ PWDF_OBJECT_ATTRIBUTES DefaultChildListAttributes
);
*/

typedef struct _WDF_CHILD_LIST_CONFIG {
  ULONG                                                   Size;
  ULONG                                                   IdentificationDescriptionSize;
  ULONG                                                   AddressDescriptionSize;
  PVOID                        EvtChildListCreateDevice;
  PVOID                    EvtChildListScanForChildren;
  PVOID      EvtChildListIdentificationDescriptionCopy;
  PVOID EvtChildListIdentificationDescriptionDuplicate;
  PVOID   EvtChildListIdentificationDescriptionCleanup;
  PVOID   EvtChildListIdentificationDescriptionCompare;
  PVOID             EvtChildListAddressDescriptionCopy;
  PVOID        EvtChildListAddressDescriptionDuplicate;
  PVOID          EvtChildListAddressDescriptionCleanup;
  PVOID                  EvtChildListDeviceReenumerated;
} WDF_CHILD_LIST_CONFIG, *PWDF_CHILD_LIST_CONFIG;


typedef struct _WDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER {
    //
    // Size in bytes of the entire description, including this header.
    //
    // Same value as WDF_CHILD_LIST_CONFIG::IdentificationDescriptionSize
    // Used as a sanity check.
    //
    ULONG IdentificationDescriptionSize;
}   WDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER,
  *PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER;

/*
NTSTATUS EvtWdfChildListCreateDevice(
  PVOID ChildList,
  PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER IdentificationDescription,
  PVOID ChildInit
)

NTSTATUS EvtWdfChildListIdentificationDescriptionDuplicate(
  PVOID ChildList,
  PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER SourceIdentificationDescription,
  PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER DestinationIdentificationDescription
)


EVT_WDF_CHILD_LIST_IDENTIFICATION_DESCRIPTION_COMPARE EvtWdfChildListIdentificationDescriptionCompare;

BOOLEAN EvtWdfChildListIdentificationDescriptionCompare(
  PVOID ChildList,
  PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER FirstIdentificationDescription,
  PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER SecondIdentificationDescription
)


void EvtWdfChildListIdentificationDescriptionCleanup(
  WDFCHILDLIST ChildList,
  PWDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER IdentificationDescription
)

*/


/*
PIRP WdfRequestWdmGetIrp(
  _In_ WDFREQUEST Request
);
Returns the WDM IRP structure that is associated with a specified framework request object.
*/


// WdfDeviceInitAssignWdmIrpPreprocessCallback
/*
NTSTATUS WdfDeviceInitAssignWdmIrpPreprocessCallback(
  PVOID                  DeviceInit,
  PVOID EvtDeviceWdmIrpPreprocess,
  UCHAR                            MajorFunction,
  PUCHAR                           MinorFunctions,
  ULONG                            NumMinorFunctions
);
*/


// Stripped version of this structure so it fits most binaries out there
typedef struct _WDFFUNCTIONS {
    PVOID                                    pfnWdfChildListCreate;
    PVOID                                 pfnWdfChildListGetDevice;
    PVOID                               pfnWdfChildListRetrievePdo;
    PVOID                pfnWdfChildListRetrieveAddressDescription;
    PVOID                                 pfnWdfChildListBeginScan;
    PVOID                                   pfnWdfChildListEndScan;
    PVOID                            pfnWdfChildListBeginIteration;
    PVOID                        pfnWdfChildListRetrieveNextDevice;
    PVOID                              pfnWdfChildListEndIteration;
    PVOID      pfnWdfChildListAddOrUpdateChildDescriptionAsPresent;
    PVOID           pfnWdfChildListUpdateChildDescriptionAsMissing;
    PVOID       pfnWdfChildListUpdateAllChildDescriptionsAsPresent;
    PVOID                         pfnWdfChildListRequestChildEject;
    PVOID                                   pfnWdfCollectionCreate;
    PVOID                                 pfnWdfCollectionGetCount;
    PVOID                                      pfnWdfCollectionAdd;
    PVOID                                   pfnWdfCollectionRemove;
    PVOID                               pfnWdfCollectionRemoveItem;
    PVOID                                  pfnWdfCollectionGetItem;
    PVOID                             pfnWdfCollectionGetFirstItem;
    PVOID                              pfnWdfCollectionGetLastItem;
    PVOID                                 pfnWdfCommonBufferCreate;
    PVOID               pfnWdfCommonBufferGetAlignedVirtualAddress;
    PVOID               pfnWdfCommonBufferGetAlignedLogicalAddress;
    PVOID                              pfnWdfCommonBufferGetLength;
    PVOID                          pfnWdfControlDeviceInitAllocate; // 0xC8
    PVOID           pfnWdfControlDeviceInitSetShutdownNotification;
    PVOID                          pfnWdfControlFinishInitializing;
    PVOID                               pfnWdfDeviceGetDeviceState;
    PVOID                               pfnWdfDeviceSetDeviceState;
    PVOID                        pfnWdfWdmDeviceGetWdfDeviceHandle;
    PVOID                           pfnWdfDeviceWdmGetDeviceObject;
    PVOID                         pfnWdfDeviceWdmGetAttachedDevice;
    PVOID                         pfnWdfDeviceWdmGetPhysicalDevice;
    PVOID                   pfnWdfDeviceWdmDispatchPreprocessedIrp;
    PVOID                pfnWdfDeviceAddDependentUsageDeviceObject;
    PVOID            pfnWdfDeviceAddRemovalRelationsPhysicalDevice;
    PVOID         pfnWdfDeviceRemoveRemovalRelationsPhysicalDevice;
    PVOID                 pfnWdfDeviceClearRemovalRelationsDevices;
    PVOID                                    pfnWdfDeviceGetDriver;
    PVOID                           pfnWdfDeviceRetrieveDeviceName;
    PVOID                        pfnWdfDeviceAssignMofResourceName;
    PVOID                                  pfnWdfDeviceGetIoTarget;
    PVOID                            pfnWdfDeviceGetDevicePnpState;
    PVOID                          pfnWdfDeviceGetDevicePowerState;
    PVOID                    pfnWdfDeviceGetDevicePowerPolicyState;
    PVOID                         pfnWdfDeviceAssignS0IdleSettings;
    PVOID                         pfnWdfDeviceAssignSxWakeSettings;
    PVOID                              pfnWdfDeviceOpenRegistryKey;
    PVOID                        pfnWdfDeviceSetSpecialFileSupport;
    PVOID                           pfnWdfDeviceSetCharacteristics;
    PVOID                           pfnWdfDeviceGetCharacteristics;
    PVOID                      pfnWdfDeviceGetAlignmentRequirement;
    PVOID                      pfnWdfDeviceSetAlignmentRequirement;
    PVOID                                     pfnWdfDeviceInitFree;
    PVOID                pfnWdfDeviceInitSetPnpPowerEventCallbacks;
    PVOID             pfnWdfDeviceInitSetPowerPolicyEventCallbacks;
    PVOID                  pfnWdfDeviceInitSetPowerPolicyOwnership;
    PVOID           pfnWdfDeviceInitRegisterPnpStateChangeCallback;
    PVOID         pfnWdfDeviceInitRegisterPowerStateChangeCallback;
    PVOID    pfnWdfDeviceInitRegisterPowerPolicyStateChangeCallback;
    PVOID                                pfnWdfDeviceInitSetIoType;
    PVOID                             pfnWdfDeviceInitSetExclusive;
    PVOID                      pfnWdfDeviceInitSetPowerNotPageable;
    PVOID                         pfnWdfDeviceInitSetPowerPageable;
    PVOID                           pfnWdfDeviceInitSetPowerInrush;
    PVOID                            pfnWdfDeviceInitSetDeviceType;
    PVOID                               pfnWdfDeviceInitAssignName;
    PVOID                         pfnWdfDeviceInitAssignSDDLString; //0x220
    PVOID                           pfnWdfDeviceInitSetDeviceClass;
    PVOID                       pfnWdfDeviceInitSetCharacteristics;
    PVOID                      pfnWdfDeviceInitSetFileObjectConfig;
    PVOID                     pfnWdfDeviceInitSetRequestAttributes;
    PVOID           pfnWdfDeviceInitAssignWdmIrpPreprocessCallback; // 248h
    PVOID             pfnWdfDeviceInitSetIoInCallerContextCallback; // 250h
    PVOID                                       pfnWdfDeviceCreate; // 258h
    PVOID                          pfnWdfDeviceSetStaticStopRemove;
    PVOID                        pfnWdfDeviceCreateDeviceInterface; // 268h
    PVOID                      pfnWdfDeviceSetDeviceInterfaceState;
    PVOID                pfnWdfDeviceRetrieveDeviceInterfaceString;
    PVOID                           pfnWdfDeviceCreateSymbolicLink; // 0x280
    PVOID                                pfnWdfDeviceQueryProperty;
    PVOID                        pfnWdfDeviceAllocAndQueryProperty;
    PVOID                           pfnWdfDeviceSetPnpCapabilities;
    PVOID                         pfnWdfDeviceSetPowerCapabilities;
    PVOID                 pfnWdfDeviceSetBusInformationForChildren;
    PVOID                           pfnWdfDeviceIndicateWakeStatus;
    PVOID                                    pfnWdfDeviceSetFailed;
    PVOID                              pfnWdfDeviceStopIdleNoTrack;
    PVOID                            pfnWdfDeviceResumeIdleNoTrack;
    PVOID                                pfnWdfDeviceGetFileObject;
    PVOID                               pfnWdfDeviceEnqueueRequest;
    PVOID                              pfnWdfDeviceGetDefaultQueue;
    PVOID                  pfnWdfDeviceConfigureRequestDispatching;
    PVOID                                   pfnWdfDmaEnablerCreate;
    PVOID                         pfnWdfDmaEnablerGetMaximumLength;
    PVOID          pfnWdfDmaEnablerGetMaximumScatterGatherElements;
    PVOID          pfnWdfDmaEnablerSetMaximumScatterGatherElements;
    PVOID                               pfnWdfDmaTransactionCreate;
    PVOID                           pfnWdfDmaTransactionInitialize;
    PVOID               pfnWdfDmaTransactionInitializeUsingRequest;
    PVOID                              pfnWdfDmaTransactionExecute;
    PVOID                              pfnWdfDmaTransactionRelease;
    PVOID                         pfnWdfDmaTransactionDmaCompleted;
    PVOID               pfnWdfDmaTransactionDmaCompletedWithLength;
    PVOID                    pfnWdfDmaTransactionDmaCompletedFinal;
    PVOID                  pfnWdfDmaTransactionGetBytesTransferred;
    PVOID                     pfnWdfDmaTransactionSetMaximumLength;
    PVOID                           pfnWdfDmaTransactionGetRequest;
    PVOID          pfnWdfDmaTransactionGetCurrentDmaTransferLength;
    PVOID                            pfnWdfDmaTransactionGetDevice;
    PVOID                                          pfnWdfDpcCreate;
    PVOID                                         pfnWdfDpcEnqueue;
    PVOID                                          pfnWdfDpcCancel;
    PVOID                                 pfnWdfDpcGetParentObject;
    PVOID                                       pfnWdfDpcWdmGetDpc;
    PVOID                                       pfnWdfDriverCreate;
    PVOID                              pfnWdfDriverGetRegistryPath;
    PVOID                           pfnWdfDriverWdmGetDriverObject;
    PVOID                    pfnWdfDriverOpenParametersRegistryKey;
    PVOID                        pfnWdfWdmDriverGetWdfDriverHandle;
    PVOID                            pfnWdfDriverRegisterTraceInfo;
    PVOID                        pfnWdfDriverRetrieveVersionString;
    PVOID                           pfnWdfDriverIsVersionAvailable;
    PVOID                        pfnWdfFdoInitWdmGetPhysicalDevice;
    PVOID                             pfnWdfFdoInitOpenRegistryKey;
    PVOID                               pfnWdfFdoInitQueryProperty;
    PVOID                       pfnWdfFdoInitAllocAndQueryProperty;
    PVOID                           pfnWdfFdoInitSetEventCallbacks;
    PVOID                                   pfnWdfFdoInitSetFilter;
    PVOID                   pfnWdfFdoInitSetDefaultChildListConfig;
    PVOID                               pfnWdfFdoQueryForInterface;
    PVOID                             pfnWdfFdoGetDefaultChildList;
    PVOID                                  pfnWdfFdoAddStaticChild;
    PVOID                 pfnWdfFdoLockStaticChildListForIteration;
    PVOID                         pfnWdfFdoRetrieveNextStaticChild;
    PVOID              pfnWdfFdoUnlockStaticChildListFromIteration;
    PVOID                              pfnWdfFileObjectGetFileName;
    PVOID                                 pfnWdfFileObjectGetFlags;
    PVOID                                pfnWdfFileObjectGetDevice;
    PVOID                         pfnWdfFileObjectWdmGetFileObject;
    PVOID                                    pfnWdfInterruptCreate;
    PVOID                            pfnWdfInterruptQueueDpcForIsr;
    PVOID                               pfnWdfInterruptSynchronize;
    PVOID                               pfnWdfInterruptAcquireLock;
    PVOID                               pfnWdfInterruptReleaseLock;
    PVOID                                    pfnWdfInterruptEnable;
    PVOID                                   pfnWdfInterruptDisable;
    PVOID                           pfnWdfInterruptWdmGetInterrupt;
    PVOID                                   pfnWdfInterruptGetInfo;
    PVOID                                 pfnWdfInterruptSetPolicy;
    PVOID                                 pfnWdfInterruptGetDevice;
    PVOID                                      pfnWdfIoQueueCreate; // 4C0h
    PVOID                                    pfnWdfIoQueueGetState;
    PVOID                                       pfnWdfIoQueueStart;
    PVOID                                        pfnWdfIoQueueStop;
    PVOID                           pfnWdfIoQueueStopSynchronously;
    PVOID                                   pfnWdfIoQueueGetDevice;
    PVOID                         pfnWdfIoQueueRetrieveNextRequest;
    PVOID                 pfnWdfIoQueueRetrieveRequestByFileObject;
    PVOID                                 pfnWdfIoQueueFindRequest;
    PVOID                        pfnWdfIoQueueRetrieveFoundRequest;
    PVOID                          pfnWdfIoQueueDrainSynchronously;
    PVOID                                       pfnWdfIoQueueDrain;
    PVOID                          pfnWdfIoQueuePurgeSynchronously;
    PVOID                                       pfnWdfIoQueuePurge;
    PVOID                                 pfnWdfIoQueueReadyNotify;
    PVOID                                     pfnWdfIoTargetCreate;
    PVOID                                       pfnWdfIoTargetOpen;
    PVOID                        pfnWdfIoTargetCloseForQueryRemove;
    PVOID                                      pfnWdfIoTargetClose;
    PVOID                                      pfnWdfIoTargetStart;
    PVOID                                       pfnWdfIoTargetStop;
    PVOID                                   pfnWdfIoTargetGetState;
    PVOID                                  pfnWdfIoTargetGetDevice;
    PVOID                        pfnWdfIoTargetQueryTargetProperty;
    PVOID                pfnWdfIoTargetAllocAndQueryTargetProperty;
    PVOID                          pfnWdfIoTargetQueryForInterface;
    PVOID                   pfnWdfIoTargetWdmGetTargetDeviceObject;
    PVOID                 pfnWdfIoTargetWdmGetTargetPhysicalDevice;
    PVOID                     pfnWdfIoTargetWdmGetTargetFileObject;
    PVOID                     pfnWdfIoTargetWdmGetTargetFileHandle;
    PVOID                      pfnWdfIoTargetSendReadSynchronously;
    PVOID                       pfnWdfIoTargetFormatRequestForRead;
    PVOID                     pfnWdfIoTargetSendWriteSynchronously;
    PVOID                      pfnWdfIoTargetFormatRequestForWrite;
    PVOID                     pfnWdfIoTargetSendIoctlSynchronously;
    PVOID                      pfnWdfIoTargetFormatRequestForIoctl;
    PVOID             pfnWdfIoTargetSendInternalIoctlSynchronously;
    PVOID              pfnWdfIoTargetFormatRequestForInternalIoctl;
    PVOID       pfnWdfIoTargetSendInternalIoctlOthersSynchronously;
    PVOID        pfnWdfIoTargetFormatRequestForInternalIoctlOthers;
    PVOID                                       pfnWdfMemoryCreate;
    PVOID                           pfnWdfMemoryCreatePreallocated;
    PVOID                                    pfnWdfMemoryGetBuffer;
    PVOID                                 pfnWdfMemoryAssignBuffer;
    PVOID                                 pfnWdfMemoryCopyToBuffer;
    PVOID                               pfnWdfMemoryCopyFromBuffer;
    PVOID                                pfnWdfLookasideListCreate;
    PVOID                          pfnWdfMemoryCreateFromLookaside;
    PVOID                               pfnWdfDeviceMiniportCreate;
    PVOID                               pfnWdfDriverMiniportUnload;
    PVOID                        pfnWdfObjectGetTypedContextWorker;
    PVOID                              pfnWdfObjectAllocateContext;
    PVOID                             pfnWdfObjectContextGetObject;
    PVOID                              pfnWdfObjectReferenceActual;
    PVOID                            pfnWdfObjectDereferenceActual;
    PVOID                                       pfnWdfObjectCreate;
    PVOID                                       pfnWdfObjectDelete;
    PVOID                                        pfnWdfObjectQuery;
    PVOID                                    pfnWdfPdoInitAllocate;
    PVOID                           pfnWdfPdoInitSetEventCallbacks;
    PVOID                              pfnWdfPdoInitAssignDeviceID;
    PVOID                            pfnWdfPdoInitAssignInstanceID;
    PVOID                               pfnWdfPdoInitAddHardwareID;
    PVOID                             pfnWdfPdoInitAddCompatibleID;
    PVOID                               pfnWdfPdoInitAddDeviceText;
    PVOID                            pfnWdfPdoInitSetDefaultLocale;
    PVOID                             pfnWdfPdoInitAssignRawDevice;
    PVOID                                     pfnWdfPdoMarkMissing;
    PVOID                                    pfnWdfPdoRequestEject;
    PVOID                                       pfnWdfPdoGetParent;
    PVOID               pfnWdfPdoRetrieveIdentificationDescription;
    PVOID                      pfnWdfPdoRetrieveAddressDescription;
    PVOID                        pfnWdfPdoUpdateAddressDescription;
    PVOID              pfnWdfPdoAddEjectionRelationsPhysicalDevice;
    PVOID           pfnWdfPdoRemoveEjectionRelationsPhysicalDevice;
    PVOID                   pfnWdfPdoClearEjectionRelationsDevices;
    PVOID                            pfnWdfDeviceAddQueryInterface;
    PVOID                                    pfnWdfRegistryOpenKey;
    PVOID                                  pfnWdfRegistryCreateKey;
    PVOID                                      pfnWdfRegistryClose;
    PVOID                               pfnWdfRegistryWdmGetHandle;
    PVOID                                  pfnWdfRegistryRemoveKey;
    PVOID                                pfnWdfRegistryRemoveValue;
    PVOID                                 pfnWdfRegistryQueryValue;
    PVOID                                pfnWdfRegistryQueryMemory;
    PVOID                           pfnWdfRegistryQueryMultiString;
    PVOID                         pfnWdfRegistryQueryUnicodeString;
    PVOID                                pfnWdfRegistryQueryString;
    PVOID                                 pfnWdfRegistryQueryULong;
    PVOID                                pfnWdfRegistryAssignValue;
    PVOID                               pfnWdfRegistryAssignMemory;
    PVOID                          pfnWdfRegistryAssignMultiString;
    PVOID                        pfnWdfRegistryAssignUnicodeString;
    PVOID                               pfnWdfRegistryAssignString;
    PVOID                                pfnWdfRegistryAssignULong;
    PVOID                                      pfnWdfRequestCreate;
    PVOID                               pfnWdfRequestCreateFromIrp;
    PVOID                                       pfnWdfRequestReuse;
    PVOID                                pfnWdfRequestChangeTarget;
    PVOID               pfnWdfRequestFormatRequestUsingCurrentType;
    PVOID                 pfnWdfRequestWdmFormatUsingStackLocation;
    PVOID                                        pfnWdfRequestSend;
    PVOID                                   pfnWdfRequestGetStatus;
    PVOID                              pfnWdfRequestMarkCancelable;
    PVOID                            pfnWdfRequestUnmarkCancelable;
    PVOID                                  pfnWdfRequestIsCanceled;
    PVOID                           pfnWdfRequestCancelSentRequest;
    PVOID                          pfnWdfRequestIsFrom32BitProcess;
    PVOID                        pfnWdfRequestSetCompletionRoutine;
    PVOID                         pfnWdfRequestGetCompletionParams;
    PVOID                               pfnWdfRequestAllocateTimer;
    PVOID                                    pfnWdfRequestComplete;
    PVOID                   pfnWdfRequestCompleteWithPriorityBoost;
    PVOID                     pfnWdfRequestCompleteWithInformation;
    PVOID                               pfnWdfRequestGetParameters;
    PVOID                         pfnWdfRequestRetrieveInputMemory;
    PVOID                        pfnWdfRequestRetrieveOutputMemory;
    PVOID                         pfnWdfRequestRetrieveInputBuffer;
    PVOID                        pfnWdfRequestRetrieveOutputBuffer;
    PVOID                         pfnWdfRequestRetrieveInputWdmMdl;
    PVOID                        pfnWdfRequestRetrieveOutputWdmMdl;
    PVOID               pfnWdfRequestRetrieveUnsafeUserInputBuffer;
    PVOID              pfnWdfRequestRetrieveUnsafeUserOutputBuffer;
    PVOID                              pfnWdfRequestSetInformation;
    PVOID                              pfnWdfRequestGetInformation;
    PVOID                               pfnWdfRequestGetFileObject;
    PVOID               pfnWdfRequestProbeAndLockUserBufferForRead;
    PVOID              pfnWdfRequestProbeAndLockUserBufferForWrite;
    PVOID                            pfnWdfRequestGetRequestorMode;
    PVOID                            pfnWdfRequestForwardToIoQueue;
    PVOID                                  pfnWdfRequestGetIoQueue;
    PVOID                                     pfnWdfRequestRequeue;
    PVOID                             pfnWdfRequestStopAcknowledge;
    PVOID                                   pfnWdfRequestWdmGetIrp;
    PVOID            pfnWdfIoResourceRequirementsListSetSlotNumber;
    PVOID         pfnWdfIoResourceRequirementsListSetInterfaceType;
    PVOID          pfnWdfIoResourceRequirementsListAppendIoResList;
    PVOID          pfnWdfIoResourceRequirementsListInsertIoResList;
    PVOID                 pfnWdfIoResourceRequirementsListGetCount;
    PVOID             pfnWdfIoResourceRequirementsListGetIoResList;
    PVOID                   pfnWdfIoResourceRequirementsListRemove;
    PVOID        pfnWdfIoResourceRequirementsListRemoveByIoResList;
    PVOID                               pfnWdfIoResourceListCreate;
    PVOID                     pfnWdfIoResourceListAppendDescriptor;
    PVOID                     pfnWdfIoResourceListInsertDescriptor;
    PVOID                     pfnWdfIoResourceListUpdateDescriptor;
    PVOID                             pfnWdfIoResourceListGetCount;
    PVOID                        pfnWdfIoResourceListGetDescriptor;
    PVOID                               pfnWdfIoResourceListRemove;
    PVOID                   pfnWdfIoResourceListRemoveByDescriptor;
    PVOID                     pfnWdfCmResourceListAppendDescriptor;
    PVOID                     pfnWdfCmResourceListInsertDescriptor;
    PVOID                             pfnWdfCmResourceListGetCount;
    PVOID                        pfnWdfCmResourceListGetDescriptor;
    PVOID                               pfnWdfCmResourceListRemove;
    PVOID                   pfnWdfCmResourceListRemoveByDescriptor;
    PVOID                                       pfnWdfStringCreate;
    PVOID                             pfnWdfStringGetUnicodeString;
    PVOID                                  pfnWdfObjectAcquireLock;
    PVOID                                  pfnWdfObjectReleaseLock;
    PVOID                                     pfnWdfWaitLockCreate;
    PVOID                                    pfnWdfWaitLockAcquire;
    PVOID                                    pfnWdfWaitLockRelease;
    PVOID                                     pfnWdfSpinLockCreate;
    PVOID                                    pfnWdfSpinLockAcquire;
    PVOID                                    pfnWdfSpinLockRelease;
    PVOID                                        pfnWdfTimerCreate;
    PVOID                                         pfnWdfTimerStart;
    PVOID                                          pfnWdfTimerStop;
    PVOID                               pfnWdfTimerGetParentObject;
    PVOID                              pfnWdfUsbTargetDeviceCreate;
    PVOID                 pfnWdfUsbTargetDeviceRetrieveInformation;
    PVOID                 pfnWdfUsbTargetDeviceGetDeviceDescriptor;
    PVOID            pfnWdfUsbTargetDeviceRetrieveConfigDescriptor;
    PVOID                         pfnWdfUsbTargetDeviceQueryString;
    PVOID                 pfnWdfUsbTargetDeviceAllocAndQueryString;
    PVOID              pfnWdfUsbTargetDeviceFormatRequestForString;
    PVOID                    pfnWdfUsbTargetDeviceGetNumInterfaces;
    PVOID                        pfnWdfUsbTargetDeviceSelectConfig;
    PVOID           pfnWdfUsbTargetDeviceWdmGetConfigurationHandle;
    PVOID          pfnWdfUsbTargetDeviceRetrieveCurrentFrameNumber;
    PVOID    pfnWdfUsbTargetDeviceSendControlTransferSynchronously;
    PVOID     pfnWdfUsbTargetDeviceFormatRequestForControlTransfer;
    PVOID              pfnWdfUsbTargetDeviceIsConnectedSynchronous;
    PVOID              pfnWdfUsbTargetDeviceResetPortSynchronously;
    PVOID              pfnWdfUsbTargetDeviceCyclePortSynchronously;
    PVOID           pfnWdfUsbTargetDeviceFormatRequestForCyclePort;
    PVOID                pfnWdfUsbTargetDeviceSendUrbSynchronously;
    PVOID                 pfnWdfUsbTargetDeviceFormatRequestForUrb;
    PVOID                        pfnWdfUsbTargetPipeGetInformation;
    PVOID                          pfnWdfUsbTargetPipeIsInEndpoint;
    PVOID                         pfnWdfUsbTargetPipeIsOutEndpoint;
    PVOID                               pfnWdfUsbTargetPipeGetType;
    PVOID           pfnWdfUsbTargetPipeSetNoMaximumPacketSizeCheck;
    PVOID                    pfnWdfUsbTargetPipeWriteSynchronously;
    PVOID                 pfnWdfUsbTargetPipeFormatRequestForWrite;
    PVOID                     pfnWdfUsbTargetPipeReadSynchronously;
    PVOID                  pfnWdfUsbTargetPipeFormatRequestForRead;
    PVOID                pfnWdfUsbTargetPipeConfigContinuousReader;
    PVOID                    pfnWdfUsbTargetPipeAbortSynchronously;
    PVOID                 pfnWdfUsbTargetPipeFormatRequestForAbort;
    PVOID                    pfnWdfUsbTargetPipeResetSynchronously;
    PVOID                 pfnWdfUsbTargetPipeFormatRequestForReset;
    PVOID                  pfnWdfUsbTargetPipeSendUrbSynchronously;
    PVOID                   pfnWdfUsbTargetPipeFormatRequestForUrb;
    PVOID                     pfnWdfUsbInterfaceGetInterfaceNumber;
    PVOID                        pfnWdfUsbInterfaceGetNumEndpoints;
    PVOID                          pfnWdfUsbInterfaceGetDescriptor;
    PVOID                          pfnWdfUsbInterfaceSelectSetting;
    PVOID                 pfnWdfUsbInterfaceGetEndpointInformation;
    PVOID                        pfnWdfUsbTargetDeviceGetInterface;
    PVOID              pfnWdfUsbInterfaceGetConfiguredSettingIndex;
    PVOID                  pfnWdfUsbInterfaceGetNumConfiguredPipes;
    PVOID                      pfnWdfUsbInterfaceGetConfiguredPipe;
    PVOID                      pfnWdfUsbTargetPipeWdmGetPipeHandle;
    PVOID                              pfnWdfVerifierDbgBreakPoint;
    PVOID                                 pfnWdfVerifierKeBugCheck;
    PVOID                                  pfnWdfWmiProviderCreate;
    PVOID                               pfnWdfWmiProviderGetDevice;
    PVOID                               pfnWdfWmiProviderIsEnabled;
    PVOID                        pfnWdfWmiProviderGetTracingHandle;
} WDFFUNCTIONS, *PWDFFUNCTIONS;


#define FILE_DEVICE_8042_PORT           0x00000027
#define FILE_DEVICE_ACPI                0x00000032
#define FILE_DEVICE_BATTERY             0x00000029
#define FILE_DEVICE_BEEP                0x00000001
#define FILE_DEVICE_BUS_EXTENDER        0x0000002a
#define FILE_DEVICE_CD_ROM              0x00000002
#define FILE_DEVICE_CD_ROM_FILE_SYSTEM  0x00000003
#define FILE_DEVICE_CHANGER             0x00000030
#define FILE_DEVICE_CONTROLLER          0x00000004
#define FILE_DEVICE_DATALINK            0x00000005
#define FILE_DEVICE_DFS                 0x00000006
#define FILE_DEVICE_DFS_FILE_SYSTEM     0x00000035
#define FILE_DEVICE_DFS_VOLUME          0x00000036
#define FILE_DEVICE_DISK                0x00000007
#define FILE_DEVICE_DISK_FILE_SYSTEM    0x00000008
#define FILE_DEVICE_DVD                 0x00000033
#define FILE_DEVICE_FILE_SYSTEM         0x00000009
#define FILE_DEVICE_FIPS                0x0000003a
#define FILE_DEVICE_FULLSCREEN_VIDEO    0x00000034
#define FILE_DEVICE_INPORT_PORT         0x0000000a
#define FILE_DEVICE_KEYBOARD            0x0000000b
#define FILE_DEVICE_KS                  0x0000002f
#define FILE_DEVICE_KSEC                0x00000039
#define FILE_DEVICE_MAILSLOT            0x0000000c
#define FILE_DEVICE_MASS_STORAGE        0x0000002d
#define FILE_DEVICE_MIDI_IN             0x0000000d
#define FILE_DEVICE_MIDI_OUT            0x0000000e
#define FILE_DEVICE_MODEM               0x0000002b
#define FILE_DEVICE_MOUSE               0x0000000f
#define FILE_DEVICE_MULTI_UNC_PROVIDER  0x00000010
#define FILE_DEVICE_NAMED_PIPE          0x00000011
#define FILE_DEVICE_NETWORK             0x00000012
#define FILE_DEVICE_NETWORK_BROWSER     0x00000013
#define FILE_DEVICE_NETWORK_FILE_SYSTEM 0x00000014
#define FILE_DEVICE_NETWORK_REDIRECTOR  0x00000028
#define FILE_DEVICE_NULL                0x00000015
#define FILE_DEVICE_PARALLEL_PORT       0x00000016
#define FILE_DEVICE_PHYSICAL_NETCARD    0x00000017
#define FILE_DEVICE_PRINTER             0x00000018
#define FILE_DEVICE_SCANNER             0x00000019
#define FILE_DEVICE_SCREEN              0x0000001c
#define FILE_DEVICE_SERENUM             0x00000037
#define FILE_DEVICE_SERIAL_MOUSE_PORT   0x0000001a
#define FILE_DEVICE_SERIAL_PORT         0x0000001b
#define FILE_DEVICE_SMARTCARD           0x00000031
#define FILE_DEVICE_SMB                 0x0000002e
#define FILE_DEVICE_SOUND               0x0000001d
#define FILE_DEVICE_STREAMS             0x0000001e
#define FILE_DEVICE_TAPE                0x0000001f
#define FILE_DEVICE_TAPE_FILE_SYSTEM    0x00000020
#define FILE_DEVICE_TERMSRV             0x00000038
#define FILE_DEVICE_TRANSPORT           0x00000021
#define FILE_DEVICE_UNKNOWN             0x00000022
#define FILE_DEVICE_VDM                 0x0000002c
#define FILE_DEVICE_VIDEO               0x00000023
#define FILE_DEVICE_VIRTUAL_DISK        0x00000024
#define FILE_DEVICE_WAVE_IN             0x00000025
#define FILE_DEVICE_WAVE_OUT            0x00000026