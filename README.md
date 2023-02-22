# non_ms_binaries

C# code to create a process which blocks 3rd party DLLs to be injected in it (such as EDRs) by using the "PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON" flag, which allows only Microsoft DLLs to be injected. Then it injects shellcode in it using VirtualAllocEx + WriteProcessMemory + VirtualProtectEx + CreateRemoteThread + QueueUserAPC.

### Sources:

- [https://github.com/leoloobeek/csharp/](https://github.com/leoloobeek/csharp/)

- Rastamouse's RTO2 course