#include "test_lp.h"
#include "test_common.h"
#include "test_thread.h"

typedef struct _LP_FIB_THREAD_CONTEXT {
    int Index;
    unsigned long Result;
} LP_FIB_THREAD_CONTEXT, * PLP_FIB_THREAD_CONTEXT;

STATUS
(__cdecl _MultithreadFibonacci)(
    IN_OPT      PVOID       Context
    )
{
    PLP_FIB_THREAD_CONTEXT context = (PLP_FIB_THREAD_CONTEXT)Context;

    if (context->Index == 0 || context->Index == 1) {
        context->Result = 1;
        return STATUS_SUCCESS;
    }

    LP_FIB_THREAD_CONTEXT context1 = { 0 };
    LP_FIB_THREAD_CONTEXT context2 = { 0 };
    PTHREAD thread1 = NULL;
    PTHREAD thread2 = NULL;
    char thName[MAX_PATH];
    STATUS status;

    __try
    {
        snprintf(thName, MAX_PATH, "Fib -%d", context->Index);

        status = ThreadCreate(thName, ThreadPriorityDefault, _MultithreadFibonacci, &context1, &thread1);
        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR(" ThreadCreate ", status);
            __leave;
        }

        snprintf(thName, MAX_PATH, "Fib -%d", context->Index);
        status = ThreadCreate(thName, ThreadPriorityDefault, _MultithreadFibonacci, &context2, &thread2);
        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR(" ThreadCreate ", status);
            __leave;
        }

        ThreadWaitForTermination(thread1, NULL);
        ThreadWaitForTermination(thread2, NULL);

        context->Result = context1.Result + context2.Result;
    }
    __finally
    {
        if (thread1)
        {
            ThreadCloseHandle(thread1);
        }
        if (thread2)
        {
            ThreadCloseHandle(thread2);
        }
    }
    return status;
}
