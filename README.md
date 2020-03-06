# X86PeRunner

Trying to run Windows X86 exe on Windows 10 ARM32 devices.

Progress:
- [x] Successfully ported unicorn(more information about unicorn below) to Win10ARM32 platform
- [x] Added PE Loader into the project which is written by mamaich(win86emu)
- [x] Load PE file into memory with unicorn hook
- [ ] Hook LoadLibraray and GetProcAdress

See Also:
+ [Unicorn](https://github.com/unicorn-engine/unicorn)
 , a lightweight, multi-platform, multi-architecture CPU emulator framework based on QEMU.
+ [Win86emu](https://forum.xda-developers.com/showthread.php?t=2095934)
 , a usermode emulator that runs leagacy x86 desktop programs on the Windows RT platform.
