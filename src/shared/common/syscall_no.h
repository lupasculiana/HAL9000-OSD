#pragma once

typedef enum _SYSCALL_ID
{
    SyscallIdIdentifyVersion,

    // Thread Management
    SyscallIdThreadExit,
    SyscallIdThreadCreate,
    SyscallIdThreadGetTid,
    SyscallIdThreadWaitForTermination,
    SyscallIdThreadCloseHandle,
    SyscallIdGetThreadPriority,
    SyscallIdSetThreadPriority,

    // Process Management
    SyscallIdProcessExit,
    SyscallIdProcessCreate,
    SyscallIdProcessGetPid,
    SyscallIdProcessWaitForTermination,
    SyscallIdProcessCloseHandle,
    SyscallIdProcessGetName,
    SyscallIdGetNumberOfThreadsForCurrentProcess,

    // Memory management 
    SyscallIdVirtualAlloc,
    SyscallIdVirtualFree,

    //Userprog.4
    SyscallIdMemset,

    //Userprog.6
    SyscallIdDisableSyscalls,

    //Userprog.7
    SyscallIdSetGlobalVariable,
    SyscallIdGetGlobalVariable,

    //Cpu management
    SyscallIdGetCurrentCpuId,
    SyscallIdGetCpuUtilization,

    //Userprog.7
    SyscallIdMutexInit,
    SyscallIdMutexAcquire,
    SyscallIdMutexRelease,

    // File management
    SyscallIdFileCreate,
    SyscallIdFileClose,
    SyscallIdFileRead,
    SyscallIdFileWrite,

    SyscallIdReserved = SyscallIdFileWrite + 1
} SYSCALL_ID;
