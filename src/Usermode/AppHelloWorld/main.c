#include "common_lib.h"
#include "syscall_if.h"
#include "um_lib_helper.h"

FUNC_ThreadStart _HelloWorldFromThread;

STATUS
__main(
    DWORD       argc,
    char**      argv
    )
{
    STATUS status;
    TID tid;
    PID pid;
    char* processName = " ";
    UM_HANDLE umHandle;

    LOG("Hello from your usermode application!\n");

    LOG("Number of arguments 0x%x\n", argc);
    LOG("Arguments at 0x%X\n", argv);
    for (DWORD i = 0; i < argc; ++i)
    {
        LOG("Argument[%u] is at 0x%X\n", i, argv[i]);
        LOG("Argument[%u] is %s\n", i, argv[i]);
    }

    //1
    
   status = SyscallProcessGetName(1, processName);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("SyscallProcessGetName", status);
        return status;
    }

    LOG("TEST1 CASE 1 Process' name is : %s\n", &processName);

    status = SyscallProcessGetName(3, processName);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("SyscallProcessGetName", status);
        return status;
    }

    LOG("TEST1 CASE 2 Process' name is : %s\n", &processName);

    status = SyscallProcessGetName(0x1234, processName);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("SyscallProcessGetName", status);
        return status;
    }

    LOG("TEST1 CASE 3 Process' name is : %s\n", &processName);

    //2

    BYTE* currentPriority = 0;
    status = SyscallGetThreadPriority(currentPriority);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("SyscallGetThreadPriority", status);
        return status;
    }
    LOG("TEST2 current thread's priority is : %d", &currentPriority);
    
    status = SyscallSetThreadPriority(16);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("SyscallSetThreadPriority", status);
        return status;
    }
    LOG("TEST2 current thread's priority after changing is : %d", &currentPriority);

    //3
    QWORD* threadCount = 0;
    BYTE* cpuId = 0;
    status = SyscallGetNumberOfThreadsForCurrentProcess(threadCount);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("SyscallGetNumberOfThreadsForCurrentProcess", status);
        return status;
    }
    status = SyscallGetCurrentCpuId(cpuId);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("SyscallGetCurrentCpuId", status);
        return status;
    }
    LOG("TEST3 current cpu's id and the number of threads started by it is : %d, %d", &threadCount, &cpuId);

    //4
    BYTE* cpuUtilization = 0;
    BYTE* id = (BYTE*)1;
    status = SyscallGetCpuUtilization(id, cpuUtilization);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("SyscallGetCpuUtilization", status);
        return status;
    }
    LOG("TEST4 current cpu's utilization %d", &cpuUtilization);

    status = SyscallGetCpuUtilization(NULL, cpuUtilization);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("SyscallGetCpuUtilization", status);
        return status;
    }
    LOG("TEST4 average cpus' utilization : %d", &cpuUtilization);

    status = SyscallThreadGetPid(UM_INVALID_HANDLE_VALUE, &pid);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("SyscallProcessGetPid", status);
        return status;
    }

    LOG("Hello from process with ID 0x%X\n", pid);


    status = SyscallThreadGetTid(UM_INVALID_HANDLE_VALUE, &tid);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("SyscallThreadGetTid", status);
        return status;
    }

    LOG("Hello from thread with ID 0x%X\n", tid);

    status = UmThreadCreate(_HelloWorldFromThread, (PVOID)(QWORD) argc, &umHandle);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("SyscallThreadCreate", status);
        return status;
    }

    //SyscallThreadCloseHandle()

    //Userprog test
     // Test SyscallProcessExit
    status = SyscallProcessExit(STATUS_SUCCESS);
    if (!SUCCEEDED(status)) {
        LOG_FUNC_ERROR("SyscallProcessExit", status);
        return;
    }
    LOG("SyscallProcessExit test passed.");

    // Test SyscallThreadExit
    status = SyscallThreadExit(STATUS_SUCCESS);
    if (!SUCCEEDED(status)) {
        LOG_FUNC_ERROR("SyscallThreadExit", status);
        return;
    }
    LOG("SyscallThreadExit test passed.");

    // Test SyscallMemset
    char buffer[10];
    status = SyscallMemset((PBYTE)buffer, sizeof(buffer), 0xFF);
    if (!SUCCEEDED(status)) {
        LOG_FUNC_ERROR("SyscallMemset", status);
        return;
    }
    LOG("SyscallMemset test passed.");

    // Test SyscallProcessCreate
    UM_HANDLE processHandle;
    status = SyscallProcessCreate("TestProcess", 0, NULL, 0, &processHandle);
    if (!SUCCEEDED(status)) {
        LOG_FUNC_ERROR("SyscallProcessCreate", status);
        return;
    }
    LOG("SyscallProcessCreate test passed. Process handle: %p", processHandle);

    // Test SyscallDisableSyscalls
    status = SyscallDisableSyscalls(TRUE); // Disable syscalls
    if (!SUCCEEDED(status)) {
        LOG_FUNC_ERROR("SyscallDisableSyscalls", status);
        return;
    }
    LOG("SyscallDisableSyscalls test passed. Syscalls disabled.");

    // Test SyscallGetGlobalVariable
    QWORD value;
    status = SyscallGetGlobalVariable("TestVariable", 0, &value);
    if (!SUCCEEDED(status)) {
        LOG_FUNC_ERROR("SyscallGetGlobalVariable", status);
        return;
    }
    LOG("SyscallGetGlobalVariable test passed. Value: %llu", value);

    // Test SyscallSetGlobalVariable
    status = SyscallSetGlobalVariable("TestVariable", 0, 42);
    if (!SUCCEEDED(status)) {
        LOG_FUNC_ERROR("SyscallSetGlobalVariable", status);
        return;
    }
    LOG("SyscallSetGlobalVariable test passed.");

    // Test SyscallMutexInit
    UM_HANDLE mutex;
    status = SyscallMutexInit(&mutex);
    if (!SUCCEEDED(status)) {
        LOG_FUNC_ERROR("SyscallMutexInit", status);
        return;
    }
    LOG("SyscallMutexInit test passed. Mutex handle: %p", mutex);

    // Test SyscallMutexAcquire
    status = SyscallMutexAcquire(mutex);
    if (!SUCCEEDED(status)) {
        LOG_FUNC_ERROR("SyscallMutexAcquire", status);
        return;
    }
    LOG("SyscallMutexAcquire test passed.");

    // Test SyscallMutexRelease
    status = SyscallMutexRelease(mutex);
    if (!SUCCEEDED(status)) {
        LOG_FUNC_ERROR("SyscallMutexRelease", status);
        return;
    }
    LOG("SyscallMutexRelease test passed.");

    // Enable syscalls again
    status = SyscallDisableSyscalls(FALSE);
    if (!SUCCEEDED(status)) {
        LOG_FUNC_ERROR("SyscallDisableSyscalls", status);
        return;
    }
    LOG("Syscalls re-enabled.");
    return STATUS_SUCCESS;
}

STATUS
(__cdecl _HelloWorldFromThread)(
    IN_OPT      PVOID       Context
    )
{
    STATUS status;
    TID tid;

    ASSERT(Context != NULL);

    status = SyscallThreadGetTid(UM_INVALID_HANDLE_VALUE, &tid);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("SyscallThreadGetTid", status);
        return status;
    }

    LOG("Hello from thread with ID 0x%X\n", tid);
    LOG("Context is 0x%X\n", Context);

    return status;
}
