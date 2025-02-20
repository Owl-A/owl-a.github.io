---
layout:     post
title:      Serial Experiments PreviousMode
date:       2025-02-19 18:04:00
summary:    Something interesting I found while debugging the Windows 11 kernel.
categories: 
- Windows 11
thumbnail: windows
tags:
- Reversing
- Mitigation
- Windows 11 
- 24H2
---
So I don't usually get the ~~dis~~pleasure of writing about windows often. Mainly because sometime in '22, I decided to only write exclusively about CTF challenges (Something that I plan on changing with this post) given that they either have some unique factor, clearly show the effort on part of the challenge setter and/or were just whacky or a pleasure to attempt.

Enter Windows 11 24H2. This has enabled a few mitigations that were long pending and apparently not too difficult to implement from my limited (maybe even flawed) judgement. One annoying change is that `NtQuerySystemInformation` no longer leaks any kernel addresses which was a bummer because now memory leaks have a price (OK, maybe not everything is so bad afterall).

That wasn't even the thing that shocked me to be fully honest...

## Previously on Windows!

So where do we even start. So theres this thing called previous mode ([a good reference](https://googleprojectzero.blogspot.com/2019/03/windows-kernel-logic-bug-class-access.html)) on `nt!_KTHREAD` at offset `0x232` which has remained stable for entirity of Windows 10 at least. Quite a lot of APIs check this value, for example, `NtReadVirtualMemory` and `NtWriteVirtualMemory`. If it is `0` the request is treated as originating from kernel itself, essentially saying, _"hey man! no need to recheck things I'm passing to you since I'm kernel already"_. So you can basically pass a kernel pointer to these APIs and get an Arbitrary read and write respectively.

What I did was in context of other Driver, but I'll use `Beep.sys` for demonstration. This is an example code I whipped up from [somewhere](https://gist.github.com/nir9/dd09bcb8b47874d5b719fef24f05eecd) with a small modification.

```c
#include <stdio.h>
#include <cstdint>
#include <Windows.h>

struct Beep
{
    uint32_t freq;
    uint32_t duration;
};

void main()
{
    HANDLE handle = CreateFileA("\\\\.\\GLOBALROOT\\Device\\Beep", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    ULONG code = 0x10000;

    __debugbreak();

    for (int i = 0;; i += 10)
    {
        struct Beep input = {};
        input.freq = 2000 + i;
        input.duration = 50;
        DeviceIoControl(handle, code, &input, sizeof(input), nullptr, 0, nullptr, nullptr);
        Sleep(100);
    }
    CloseHandle(handle);
}
```

So I ran this on Windows 10 1809. And did this on the `__debugbreak`.

![__debugbreak hit on windows 10](/images/2025-02-19-Serial-Experiments-PreviousMode/first_dbg_win10.png)

I continued till the br... you know the drill. And well then I overwrote the current thread's `PreviousMode` (one which hit breakpoint) to `0` which is equivalent to Kernel mode.

![BeepDeviceControl Reached](/images/2025-02-19-Serial-Experiments-PreviousMode/first_bp_win10.png)

Removed the breakpoint; hit continue.... Nothing.

![Crickets...](/images/2025-02-19-Serial-Experiments-PreviousMode/crickets.png)

Well, not unexpected... but this is what Win11 26100.1150 insider gave me (This was at a time this was insider but now I'm pretty sure they have deployed it).

![Why is this crashing](/images/2025-02-19-Serial-Experiments-PreviousMode/lowcost_wait_what.jpg)<font style="font-size:70%;color:gray"> <small>Credits: IG @lowcostcosplayth. Do check him out. really good cosplayer btw.

Well. Since when did we start checking if previous mode was restored and how/where are we keeping the track of this! I was always under the impression that Previous mode was gospel truth to the kernel but here we are slapping on the equivalent of reverse edge CFI onto its sanctity! Blasphemy!

Anywho, I'll do what I do best on a cold winter night with a mug of hot chocolate (just kidding, where I live we have only summer and rain but _its fun to fan-ta-size_), slap a hardware breakpoint on PreviousMode before hitting the kernel and try to figure out a likely bypass.

## PreviousMode's Bizzare Adventures

_<font style="font-size:70%;color:gray">*Puts on Giorno's Theme*</font>_

I hope I don't need to show all my work here (unlike my grade 8 maths teacher... cough cough) but believe me when I say I placed a hardware breakpoint on PreviousMode of current thread and the first read is surprisingly before the debugger even returns back control! The code listing shows the instruction that actually does the access since hardware breakpoints halt at the following instruction.

![Return from the debugger](/images/2025-02-19-Serial-Experiments-PreviousMode/stacktrace_first_hw_hit.png)

```plaintext
nt!KiExecuteAllDpcs+0x379:
   fffff803`98c81689 488b4c2468      mov     rcx,qword ptr [rsp+68h]
   fffff803`98c8168e 8b81e4010000    mov     eax,dword ptr [rcx+1E4h]
   fffff803`98c81694 89442444        mov     dword ptr [rsp+44h],eax
   fffff803`98c81698 89842490000000  mov     dword ptr [rsp+90h],eax
=> fffff803`98c8169f 0fb68132020000  movzx   eax,byte ptr [rcx+232h]
   fffff803`98c816a6 88442430        mov     byte ptr [rsp+30h],al
   fffff803`98c816aa 88442431        mov     byte ptr [rsp+31h],al
   fffff803`98c816ae 488b9424e0000000 mov     rdx,qword ptr [rsp+0E0h]
   fffff803`98c816b6 8b02            mov     eax,dword ptr [rdx]
```

Sorry to admit but the next "logical" step in my head was to trace the instruction stream while manually tainting using hardware breakpoints. To put this into perspective, it's past 0100 hrs as I type this and I really dont have the patience to load `ntoskrnl.exe` into IDA and have that little maneuver cost me 51 years. (Spoiler alert, it costed me double) Here goes nothing...

Before going ham on this, let's just make sure we're in interesting territory. Since, the diagnostic message said mismatch on return from driver, I'll just make sure we start tracing from when we return from `nt!KiBreakpointTrap`... Wait. Why am I getting a huge spam of `nt!KiExceptionDispatch`... Oooh... oh.. OHHH!

Well if you look at the top of stack, you find that its `nt!KiExecuteAllDpcs`. Well, any driver can schedule a DPC, so you have to check if the PreviousMode changed before and after the call! Well, it's not that I reached the mitigation, it was the friends we made along the way... Sigh. IDA, old friend, how much time will you need?

```cpp
// IN nt!KiExecuteAllDpcs
if ( PrevMode_saved != *(_BYTE *)(v145 + 0x232) )
    KeBugCheckEx(0x1F9u, *(ULONG_PTR *)&Unknown[1], *(char *)(v145 + 0x232), 4ui64, 0i64);
```

So far the situation is a bit dismal. This is in the function `nt!KiExecuteAllDpcs` and it saves the caches previous mode on the stack. If we already have a strong primitive like stack overflow, no one in their right mind would look any further.

Although I'm not adding that pseudocode, `nt!NtDeviceIoControlFile` does the usual checks if previous mode is anything but `0`. That also triggers the same read breakpoint.

```plaintext
   KiSystemCall64+520  KiSystemServiceExit:                    ; CODE XREF: KiSystemCall64+34D↑j
   KiSystemCall64+520                                          ; KiSystemCall64+CE1↓j ...
   KiSystemCall64+520                  mov     rbx, [rbp+0C0h]
   KiSystemCall64+527                  mov     rdi, [rbp+0C8h]
   KiSystemCall64+52E                  mov     rsi, [rbp+0D0h]
   KiSystemCall64+535                  mov     r11, gs:188h
   KiSystemCall64+53E                  test    byte ptr [rbp+0F0h], 1
   KiSystemCall64+545                  jz      loc_14068A67E
   KiSystemCall64+54B                  mov     rcx, cr8
   KiSystemCall64+54F                  or      cl, [r11+24Ah]
   KiSystemCall64+556                  or      ecx, [r11+1E4h]
   KiSystemCall64+55D                  jnz     loc_14068AA31
=> KiSystemCall64+563                  cmp     byte ptr [r11+232h], 1
   KiSystemCall64+56B                  jnz     call_bugcheck
```

Well. This is worse, it's not even saving the thread state at this point! As soon as you say _I want to go back to user space_, if your PreviousMode isn't `1` we just bugcheck.

What else can we do? For a thread running in user mode, there are so few entrypoints into the kernel! One is Syscall (out of question because we check against `1` on return to user), other a slightly less controlled one is interrupts. Even in interupts, We've seen a big possible component, that is DPC has no chance of changing PreviousMode. Since, interrupts mainly schedule a deferred call which is being monitored anyway, I don't think Microsoft would take the pain of checking if the PreviousMode was modified, returning from an interrupt context!

```plaintext
0: kd> g
Breakpoint 3 hit
nt!KiProcessExpiredTimerList+0x29d:
fffff800`ad559c3d 443ae0          cmp     r12b,al
0: kd> g
Breakpoint 3 hit
nt!KiExecuteAllDpcs+0x396:
fffff800`ad4816a6 88442430        mov     byte ptr [rsp+30h],al
0: kd> 
Breakpoint 3 hit
nt!KiExecuteAllDpcs+0x90d:
fffff800`ad481c1d 38442430        cmp     byte ptr [rsp+30h],al
0: kd> 
Breakpoint 3 hit
nt!KiExecuteAllDpcs+0x396:
fffff800`ad4816a6 88442430        mov     byte ptr [rsp+30h],al
```

To put the theory to test, I set a hardware breakpoint on previous mode (yet again) of a random thread. We can see that the only times Previous Mode is read (a superset of all times is it checked against a saved/hardcoded value) is limited to either some syscall or these two functions. Although not exhaustive in my opinion, the clearly tell us APC and DPCs are both checked for Previous Mode tampering and there are no check in the "glue" or "run-time" code that invokes them, which is developed and audited by Microsoft and does not do anything semantically very interesting.

## Callback Look back

While we are on the topic, might as well inspect the usermode-kernelmode boundary exhaustively. There's not just users calling syscalls as far as windows is concerned. The rabid dog it has evolved into can bite user space from the kernel AKA _kernel callbacks_. A particular usecase, thanks to it being a microkernel is the graphics subsytem. Win32k.sys has stubs prefixed with `xxx` or `zzz` which can possibly make callbacks to usermode.

It might seem useless to think that they would not definitly set Previous Mode to `1` before calling into usermode. Well, they don't **_seem to_** do that explicitly from what I could infer at least dynamically (correct me if I'm wrong here).

```plaintext
   KiSystemCall64+2A2  KiSystemServiceUser:                    ; CODE XREF: KiSystemService:loc_1406897D5↑j
   KiSystemCall64+2A2                                          ; KiSystemCall64+281↑j ...
   KiSystemCall64+2A2                  mov     byte ptr [rbp-55h], 2
   KiSystemCall64+2A6                  mov     byte ptr [rbp-58h], 1
   KiSystemCall64+2AA                  mov     rbx, gs:188h
=> KiSystemCall64+2B3                  mov     byte ptr [rbx+232h], 1
   KiSystemCall64+2BA                  prefetchw byte ptr [rbx+90h]
   KiSystemCall64+2C1                  stmxcsr dword ptr [rbp-54h]
   KiSystemCall64+2C5                  ldmxcsr dword ptr gs:180h
   KiSystemCall64+2CE                  mov     [rbp-38h], r8
```

Also, assuming somehow you even got hold of Previous Mode `0` in user callback, Another issue is escalation. At start of syscall dispatch the previous mode is explicitly forced to `1`. Best you can do is another Previous Mode mismatch crash if you do manage to null it out while jumping to the callback.

## Conclusion

As of now, this mitigation does seem air tight. Really there's not much to this "mitigation"; no clever tricks, no undocumented/opaque structure juggling, no support from hypervisor or secure kernel (Read: _Nightmare_), and no redundancy like in case of requestor and previous mode.

![horror](/images/2025-02-19-Serial-Experiments-PreviousMode/horror.png)

This seemed like a perfect opportunity for a blog, quite shamelessly and I think I'd focus on more involved mitigations in the near future. till then...

![To be continued...](/images/2025-02-19-Serial-Experiments-PreviousMode/tbc.png)

<font style="font-size:70%;color:gray">*Roundabout starts playing in the distance*</font>
