#include "HAL9000.h"
#include "syscall.h"
#include "gdtmu.h"
#include "syscall_defs.h"
#include "syscall_func.h"
#include "syscall_no.h"
#include "mmu.h"
#include "process_internal.h"
#include "dmp_cpu.h"
#include "thread.h"
#include "thread_internal.h"
#include "cpumu.h"
#include "process_internal.h"
#include "acpi_interface.h"
#include "synch.h"
#include "ex_event.h"
#include "core.h"
#include "vmm.h"
#include "isr.h"
#include "pe_exports.h"
#include "base.h"
#include "smp.h"
#include "mutex.h"
//#include "thread_defs.h"

extern void SyscallEntry();
extern PPCPU _CpuReferenceById();
#define SYSCALL_IF_VERSION_KM       SYSCALL_IMPLEMENTED_IF_VERSION

//Userprog.6
typedef struct _SYSCALL_SYSTEM_DATA
{
    BOOLEAN activateSyscalls;
    LOCK         AllVariablesLock;

    _Guarded_by_(AllVariablesLock)
    LIST_ENTRY    sharedVariablesList;

} SYSCALL_SYSTEM_DATA, * PSYSCALL_SYSTEM_DATA;

static SYSCALL_SYSTEM_DATA m_syscallData;

//Userprog.7
typedef struct _SYSCALL_SHARED_VARIABLE
{
    char* VariableName;
    QWORD sharedValue;
    LIST_ENTRY    sharedVariablesList;

} SYSCALL_SHARED_VARIABLE, * PSYSCALL_SHARED_VARIABLE;



void
SyscallHandler(
    INOUT   COMPLETE_PROCESSOR_STATE    *CompleteProcessorState
    )
{
    SYSCALL_ID sysCallId;
    PQWORD pSyscallParameters;
    PQWORD pParameters;
    STATUS status;
    REGISTER_AREA* usermodeProcessorState;

    ASSERT(CompleteProcessorState != NULL);

    // It is NOT ok to setup the FMASK so that interrupts will be enabled when the system call occurs
    // The issue is that we'll have a user-mode stack and we wouldn't want to receive an interrupt on
    // that stack. This is why we only enable interrupts here.
    ASSERT(CpuIntrGetState() == INTR_OFF);
    CpuIntrSetState(INTR_ON);

    LOG_TRACE_USERMODE("The syscall handler has been called!\n");

    status = STATUS_SUCCESS;
    pSyscallParameters = NULL;
    pParameters = NULL;
    usermodeProcessorState = &CompleteProcessorState->RegisterArea;

    __try
    {
        if (LogIsComponentTraced(LogComponentUserMode))
        {
            DumpProcessorState(CompleteProcessorState);
        }

        // Check if indeed the shadow stack is valid (the shadow stack is mandatory)
        pParameters = (PQWORD)usermodeProcessorState->RegisterValues[RegisterRbp];
        status = MmuIsBufferValid(pParameters, SHADOW_STACK_SIZE, PAGE_RIGHTS_READ, GetCurrentProcess());
        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR("MmuIsBufferValid", status);
            __leave;
        }

        sysCallId = usermodeProcessorState->RegisterValues[RegisterR8];

        LOG_TRACE_USERMODE("System call ID is %u\n", sysCallId);

        // The first parameter is the system call ID, we don't care about it => +1
        pSyscallParameters = (PQWORD)usermodeProcessorState->RegisterValues[RegisterRbp] + 1;

        // Dispatch syscalls
        switch (sysCallId)
        {
        case SyscallIdIdentifyVersion:
            status = SyscallValidateInterface((SYSCALL_IF_VERSION)*pSyscallParameters);
            break;
        // STUDENT TODO: implement the rest of the syscalls
        case SyscallIdFileWrite:
            status = SyscallFileWrite((UM_HANDLE)pSyscallParameters[0],
                (PVOID)pSyscallParameters[1],
                (QWORD)pSyscallParameters[2],
                (QWORD*)pSyscallParameters[3]);
            break;
        case SyscallIdThreadGetTid:
            status = SyscallThreadGetTid((UM_HANDLE)pSyscallParameters[0],
                (TID*)pSyscallParameters[1]);
            break;
        case SyscallIdProcessGetName:
            status = SyscallProcessGetName((QWORD)pSyscallParameters[0],
                (char*)pSyscallParameters[1]);
            break;
        case SyscallIdGetThreadPriority:
            status = SyscallGetThreadPriority((BYTE*)pSyscallParameters[0]);
            break;
        case SyscallIdSetThreadPriority:
            status = SyscallSetThreadPriority((BYTE)pSyscallParameters[0]);
            break;
        case SyscallIdGetCurrentCpuId:
            status = SyscallGetCurrentCpuId((BYTE*)pSyscallParameters[0]);
            break;
        case SyscallIdGetNumberOfThreadsForCurrentProcess:
            status = SyscallGetNumberOfThreadsForCurrentProcess((QWORD*)pSyscallParameters[0]);
            break;
        case SyscallIdGetCpuUtilization:
            status = SyscallGetCpuUtilization((BYTE*)pSyscallParameters[0],
                (BYTE*)pSyscallParameters[1]);
            break;
        case SyscallIdMemset:
            status = SyscallMemset((PBYTE)pSyscallParameters[0],
                (WORD)pSyscallParameters[1],
                (BYTE)pSyscallParameters[2]);
            break;
        case SyscallIdDisableSyscalls:
            status = SyscallDisableSyscalls((BOOLEAN)pSyscallParameters[0]);
            break;
        case SyscallIdProcessCreate:
            status = SyscallProcessCreate((char*)pSyscallParameters[0],
                (QWORD)pSyscallParameters[1],
                (char*)pSyscallParameters[2],
                (QWORD)pSyscallParameters[3],
                (UM_HANDLE*)pSyscallParameters[4]);
            break;
        case SyscallIdGetGlobalVariable:
            status = SyscallGetGlobalVariable((char*)pSyscallParameters[0],
                (DWORD)pSyscallParameters[1],
                (PQWORD)pSyscallParameters[2]);
            break;
        case SyscallIdSetGlobalVariable:
            status = SyscallSetGlobalVariable((char*)pSyscallParameters[0],
                (DWORD)pSyscallParameters[1],
                (QWORD)pSyscallParameters[2]);
            break;
        case SyscallIdMutexInit:
            status = SyscallMutexInit((UM_HANDLE*)pSyscallParameters[0]);
            break;
        case SyscallIdMutexAcquire:
            status = SyscallMutexAcquire((UM_HANDLE)pSyscallParameters[0]);
            break;
        case SyscallIdMutexRelease:
            status = SyscallMutexRelease((UM_HANDLE)pSyscallParameters[0]);
            break;
        default:
            LOG_ERROR("Unimplemented syscall called from User-space!\n");
            status = STATUS_UNSUPPORTED;
            break;
        }

    }
    __finally
    {
        LOG_TRACE_USERMODE("Will set UM RAX to 0x%x\n", status);

        usermodeProcessorState->RegisterValues[RegisterRax] = status;

        CpuIntrSetState(INTR_OFF);
    }
}

void
SyscallPreinitSystem(
    void
    )
{

}

STATUS
SyscallInitSystem(
    void
    )
{
    return STATUS_SUCCESS;
}

STATUS
SyscallUninitSystem(
    void
    )
{
    return STATUS_SUCCESS;
}

void
SyscallCpuInit(
    void
    )
{
    IA32_STAR_MSR_DATA starMsr;
    WORD kmCsSelector;
    WORD umCsSelector;

    memzero(&starMsr, sizeof(IA32_STAR_MSR_DATA));

    kmCsSelector = GdtMuGetCS64Supervisor();
    ASSERT(kmCsSelector + 0x8 == GdtMuGetDS64Supervisor());

    umCsSelector = GdtMuGetCS32Usermode();
    /// DS64 is the same as DS32
    ASSERT(umCsSelector + 0x8 == GdtMuGetDS32Usermode());
    ASSERT(umCsSelector + 0x10 == GdtMuGetCS64Usermode());

    // Syscall RIP <- IA32_LSTAR
    __writemsr(IA32_LSTAR, (QWORD) SyscallEntry);

    LOG_TRACE_USERMODE("Successfully set LSTAR to 0x%X\n", (QWORD) SyscallEntry);

    // Syscall RFLAGS <- RFLAGS & ~(IA32_FMASK)
    __writemsr(IA32_FMASK, RFLAGS_INTERRUPT_FLAG_BIT);

    LOG_TRACE_USERMODE("Successfully set FMASK to 0x%X\n", RFLAGS_INTERRUPT_FLAG_BIT);

    // Syscall CS.Sel <- IA32_STAR[47:32] & 0xFFFC
    // Syscall DS.Sel <- (IA32_STAR[47:32] + 0x8) & 0xFFFC
    starMsr.SyscallCsDs = kmCsSelector;

    // Sysret CS.Sel <- (IA32_STAR[63:48] + 0x10) & 0xFFFC
    // Sysret DS.Sel <- (IA32_STAR[63:48] + 0x8) & 0xFFFC
    starMsr.SysretCsDs = umCsSelector;

    __writemsr(IA32_STAR, starMsr.Raw);

    LOG_TRACE_USERMODE("Successfully set STAR to 0x%X\n", starMsr.Raw);
}

// SyscallIdIdentifyVersion
//Userprog.1 - " Make the changes required to run user applications: setting up the user stack,
//implementing SyscallIdIdentifyVersion, SyscallIdProcessExit, and SyscallIdThreadExit."
STATUS
SyscallValidateInterface(
    IN  SYSCALL_IF_VERSION          InterfaceVersion
)
{
    LOG_TRACE_USERMODE("Will check interface version 0x%x from UM against 0x%x from KM\n",
        InterfaceVersion, SYSCALL_IF_VERSION_KM);

    if (InterfaceVersion != SYSCALL_IF_VERSION_KM)
    {
        LOG_ERROR("Usermode interface 0x%x incompatible with KM!\n", InterfaceVersion);
        return STATUS_INCOMPATIBLE_INTERFACE;
    }

    return STATUS_SUCCESS;
}

//Userprog.2 - "Implement the write to UM_FILE_HANDLE_STDOUT system call."
STATUS
SyscallFileWrite(
    IN  UM_HANDLE                   FileHandle,
    IN_READS_BYTES(BytesToWrite)
    PVOID                           Buffer,
    IN  QWORD                       BytesToWrite,
    OUT QWORD* BytesWritten
)
{
    if (BytesWritten == NULL || Buffer == NULL || strlen_s(Buffer, MAX_PATH) > BytesToWrite || MmuIsBufferValid(Buffer,strlen(Buffer), PAGE_RIGHTS_WRITE,GetCurrentProcess()))
    {
        return STATUS_UNSUCCESSFUL;
    }

    if (FileHandle == UM_FILE_HANDLE_STDOUT)
    {
        *BytesWritten = BytesToWrite;
        LOG("Message written : %s\n", Buffer);

        return STATUS_SUCCESS;
    }

    *BytesWritten = BytesToWrite;
    return STATUS_SUCCESS;
}

STATUS
SyscallThreadGetTid(
    IN_OPT UM_HANDLE ThreadHandle,
    OUT TID* ThreadId
)
{
    if (ThreadHandle == UM_INVALID_HANDLE_VALUE)
    {
        *ThreadId = GetCurrentThread()->Id;
        return STATUS_SUCCESS;
    }

    *ThreadId = ((PTHREAD)ThreadHandle)->Id;
    return STATUS_SUCCESS;
}

STATUS
SyscallProcessGetName(
    IN QWORD                ProcessNameMaxLen,
    OUT char* ProcessName
)
{
    PPROCESS process = GetCurrentProcess();
    if (ProcessName == NULL || ProcessNameMaxLen/10 == 0)
    {
        return STATUS_INVALID_PARAMETER2;
    }
    int result = 0;
    result = snprintf(ProcessName, (DWORD) ProcessNameMaxLen, "%s", process->ProcessName);
    if (result < 0) {
        return STATUS_TRUNCATED_PROCESS_NAME;
    }

    return STATUS_SUCCESS;
}

STATUS
SyscallGetThreadPriority(
    OUT BYTE* ThreadPriority
)
{
    PTHREAD pThread = GetCurrentThread();
    if (pThread->Priority == ThreadPriorityDefault) {
        *ThreadPriority = (BYTE)16;
    }
    else if (pThread->Priority == ThreadPriorityMaximum) {
        *ThreadPriority = (BYTE)31;
    }
    else if (pThread->Priority == ThreadPriorityLowest) {
        *ThreadPriority = (BYTE)0;
    }

    return STATUS_SUCCESS;
}

STATUS
SyscallSetThreadPriority(
    IN BYTE ThreadPriority
)
{
    PTHREAD currentThread = GetCurrentThread();

    if (ThreadPriority != ThreadPriorityLowest &&
        ThreadPriority != ThreadPriorityDefault &&
        ThreadPriority != ThreadPriorityMaximum)
    {
        return STATUS_INVALID_PARAMETER1;
    }

    currentThread->Priority = (THREAD_PRIORITY)ThreadPriority;
    return STATUS_SUCCESS;
}

STATUS
SyscallGetCurrentCpuId(
    OUT BYTE* CpuId
)
{
    PPCPU currentPcpu = GetCurrentPcpu();

    *CpuId = (BYTE)currentPcpu->ApicId;

    return STATUS_SUCCESS;
}

STATUS
SyscallGetNumberOfThreadsForCurrentProcess(
    OUT QWORD* ThreadNo
)
{
    INTR_STATE oldIntrState;
    PPROCESS currentProcess = GetCurrentProcess();

    LockAcquire(&currentProcess->ThreadListLock, &oldIntrState);
    *ThreadNo = (QWORD)currentProcess->NumberOfThreads;
    LockRelease(&currentProcess->ThreadListLock, oldIntrState);

    return STATUS_SUCCESS;
}

QWORD calculateUtilization(PPCPU pCpu) {
    QWORD totalTicks;
    QWORD idleTicks;
    QWORD cpuUtilization;

    totalTicks = pCpu->ThreadData.RunningThreadTicks + pCpu->ThreadData.IdleTicks;
    idleTicks = pCpu->ThreadData.IdleTicks;

    if (totalTicks == 0)
    {
        return 0;
    }

    cpuUtilization = ((totalTicks - idleTicks) * 100) / totalTicks;
    return cpuUtilization;
}

STATUS
SyscallGetCpuUtilization(
    IN_OPT BYTE* CpuId,
    OUT BYTE* Utilization
)
{
    PPCPU pCpu;
    QWORD cpuUtilization;

    if (CpuId == NULL)
    {
        PLIST_ENTRY pCpuListHead;
        SmpGetCpuList(&pCpuListHead);

        LIST_ENTRY* entry;
        for (entry = pCpuListHead->Flink; entry != pCpuListHead; entry = entry->Flink) {
            PCPU* cpu = CONTAINING_RECORD(entry, PCPU, ListEntry);
            cpuUtilization = calculateUtilization(cpu);
        }
    }
    if (*CpuId == 1) {
        pCpu = GetCurrentPcpu();
        cpuUtilization = calculateUtilization(pCpu);
    }
    else
    {
        APIC_ID apicId = *CpuId;
        pCpu = _CpuReferenceById(apicId);
        if (pCpu == NULL)
        {
            return STATUS_CPU_NO_MATCHES;
        }
        cpuUtilization = calculateUtilization(pCpu);
    }

    if (cpuUtilization == 0)
    {
        return STATUS_UNSUCCESSFUL;
    }

    *Utilization = (BYTE)cpuUtilization;

    return STATUS_SUCCESS;
}

//Userprog.1 - " Make the changes required to run user applications: setting up the user stack,
//implementing SyscallIdIdentifyVersion, SyscallIdProcessExit, and SyscallIdThreadExit."
STATUS
SyscallProcessExit(
    IN      STATUS                  ExitStatus
)
{
    PPROCESS Process = GetCurrentProcess();
    Process->TerminationStatus = ExitStatus;
    ProcessTerminate(Process);

    return STATUS_SUCCESS;
}

//Userprog.1 - " Make the changes required to run user applications: setting up the user stack,
//implementing SyscallIdIdentifyVersion, SyscallIdProcessExit, and SyscallIdThreadExit."
STATUS
SyscallThreadExit(
    IN  STATUS                      ExitStatus
)
{
    ThreadExit(ExitStatus);

    return STATUS_SUCCESS;
}

//Userprog.4 - "Implement a system call SyscallIdMemset which effectively does a memset on a requested virtual address. 
//In the corresponding system call handler check if the pointer receives as a parameter is valid or not." 
STATUS
SyscallMemset(
    OUT_WRITES(BytesToWrite)    PBYTE   Address,
    IN                          DWORD   BytesToWrite,
    IN                          BYTE    ValueToWrite
)
{
    if (&BytesToWrite == NULL || &ValueToWrite == NULL ||  MmuIsBufferValid(Address, strlen((char*)Address), PAGE_RIGHTS_WRITE, GetCurrentProcess()))
    {
        return STATUS_UNSUCCESSFUL;
    }

    memset(Address, ValueToWrite, BytesToWrite);
    return STATUS_SUCCESS;
}

//Userprog.5 - "Maintain the list of children for each process. If the parent of a process dies,
//you should move the dying process children to have as the parent the system process."
STATUS
SyscallProcessCreate(
    IN_READS_Z(PathLength)
    char* ProcessPath,
    IN          QWORD               PathLength,
    IN_READS_OPT_Z(ArgLength)
    char* Arguments,
    IN          QWORD               ArgLength,
    OUT         UM_HANDLE* ProcessHandle
)
{

    if (m_syscallData.activateSyscalls) {
        PPROCESS pProcess;
        INTR_STATE oldIntrState;

        if (PathLength <= 0 || ArgLength <= 0) {
            return STATUS_INVALID_PARAMETER1;
        }

        STATUS status = ProcessCreate(ProcessPath, Arguments, &pProcess);

        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR("Process creation failed", status);

            return STATUS_UNSUCCESSFUL;
        }

        LockAcquire(&GetCurrentProcess()->ChildrenListLock, &oldIntrState);
        InsertTailList(&GetCurrentProcess()->ChildrenList, (PLIST_ENTRY)pProcess);
        LockRelease(&GetCurrentProcess()->ChildrenListLock, oldIntrState);

        *ProcessHandle = (UM_HANDLE)pProcess;
    }
    
    return STATUS_SUCCESS;
}

//Userprog.6 - "Implement a new system call SyscallIdDisableSyscalls
// which depending on the parameter either disables all other system calls effectively causing them to fail or enables them."
STATUS
SyscallDisableSyscalls(
    IN      BOOLEAN     Disable
)
{
    // When Disable == TRUE => all system calls except SyscallDisableSyscalls will fail
    // When Disable == FALSE => all system calls work normally
    if (Disable == TRUE || Disable == FALSE) {
        m_syscallData.activateSyscalls = Disable;
    }
    else {
        return STATUS_INVALID_PARAMETER1;
    }
    
    return STATUS_SUCCESS;
    //all syscalls's code should be included in an if(m_syscallData.activateSyscalls){ ...existing code} to check whether they are enabled or disabled
    //I included this example on the previous syscall, SyscallProcessCreate, and will include in upcoming syscalls
}

//Userprog.7 - "Implement two system calls SyscallIdSetGlobalVariable and SyscallIdGetGlobalVariable for processes to be able to share information."
STATUS
SyscallGetGlobalVariable(
    IN_READS_Z(VarLength)           char* VariableName,
    IN                              DWORD   VarLength,
    OUT                             PQWORD  Value
)
{
    PLIST_ENTRY pListEntry;
    INTR_STATE oldState;
    PSYSCALL_SHARED_VARIABLE variable;

    LockAcquire(&m_syscallData.AllVariablesLock, &oldState);
    pListEntry = m_syscallData.sharedVariablesList.Flink;

    while (pListEntry != &m_syscallData.sharedVariablesList)
    {
        variable = CONTAINING_RECORD(pListEntry, SYSCALL_SHARED_VARIABLE, sharedVariablesList);
            if (strcmp(variable->VariableName, VariableName) == 0)
            {
                Value = &variable->sharedValue;
                LockRelease(&m_syscallData.AllVariablesLock, oldState);
            }
            pListEntry = pListEntry->Flink;

    }
    LockRelease(&m_syscallData.AllVariablesLock, oldState);
    UNREFERENCED_PARAMETER(VarLength);
    return STATUS_SUCCESS;
}

STATUS
SyscallSetGlobalVariable(
    IN_READS_Z(VarLength)           char* VariableName,
    IN                              DWORD   VarLength,
    IN                              QWORD   Value
)
{
    PLIST_ENTRY pListEntry;
    INTR_STATE oldState;
    PSYSCALL_SHARED_VARIABLE variable;

    LockAcquire(&m_syscallData.AllVariablesLock, &oldState);
    pListEntry = m_syscallData.sharedVariablesList.Flink;

    while (pListEntry != &m_syscallData.sharedVariablesList)
    {
        variable = CONTAINING_RECORD(pListEntry, SYSCALL_SHARED_VARIABLE, sharedVariablesList);
        if (variable == NULL) {
            strcpy(variable->VariableName,VariableName);
            variable->sharedValue = Value;
            InsertTailList(&m_syscallData.sharedVariablesList, &variable->sharedVariablesList);
        }
        else {
            if (strcmp(variable->VariableName, VariableName) == 0)
            {
                variable->sharedValue = Value;
                LockRelease(&m_syscallData.AllVariablesLock, oldState);
            }
            pListEntry = pListEntry->Flink;
        }
       
    }
    LockRelease(&m_syscallData.AllVariablesLock, oldState);
    UNREFERENCED_PARAMETER(VarLength);

    return STATUS_SUCCESS;
}

//Userprog.8
STATUS
SyscallMutexInit(
    OUT         UM_HANDLE* Mutex
)
{
    if (Mutex != UM_INVALID_HANDLE_VALUE) {
       MutexInit((PMUTEX)Mutex, TRUE);
    }
    else {
        return STATUS_INVALID_PARAMETER1;
    }

    return STATUS_SUCCESS;
}

STATUS
SyscallMutexAcquire(
    IN       UM_HANDLE          Mutex
)
{
    if (Mutex != UM_INVALID_HANDLE_VALUE) {
        MutexAcquire((PMUTEX)Mutex);
    }
    else {
        return STATUS_INVALID_PARAMETER1;
    }

    return STATUS_SUCCESS;
}

STATUS
SyscallMutexRelease(
    IN       UM_HANDLE          Mutex
)
{
    if (Mutex != UM_INVALID_HANDLE_VALUE) {
        MutexRelease((PMUTEX)Mutex);
    }
    else {
        return STATUS_INVALID_PARAMETER1;
    }

    return STATUS_SUCCESS;
}

