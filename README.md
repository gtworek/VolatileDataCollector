During my Incident Response engagements, I have realized that dumping volatile data is always done bad (or at least in a way different than the best one). 
Additionally, the data is never in the same format, which makes the analysis harder (if not impossible) to automate. 

And it is why I have created my own tool for it.

It dumps:
- OS details (user name, machine name, version)
- Process details (PID, name, PPID, path, cmdline, Thread count, iocount, times)
- Loaded DLLs
- Drivers
- Environment
- Root certs (thumbnail and name, for user and machine)
- Open handles (open files, open registry entries etc.)
- ARP cache
- IP configuration
- DNS cache
- Active TCP/IP connections (addresses, ports, PID, time of establishing)
- Active logons
- Kernel memory
- BitLocker keys, including cleartext recovery passwords


It creates one text file with report, and another one for dump. Dump is optional and happens only if `-memdump` parameter is present. It is possible to specify paths for a report and dump. If no paths are specified, the same location as exe is used.

Of course, every single action is made with volatile data in mind. The tool collects it, not destroys. It is as minimalistic, as my knowledge allows, when it comes to loaded DLLs, open registry keys, etc.

The tool works better with admin permissions (can reach for all processes etc.) but it is not technically required. I am trying my best to clearly mark all cases where the information could not be obtained.

The tool works well. EXE requires Windows 10, but the source code may be easily (#define) compiled for Windows 7. Windows 7 version doesn’t create Kernel Dumps and doesn’t provide some less important hardware information, but it works nicely.

The source code requires polishing, especially when it comes to some uniformity, and error checking for string operations. I am trying to stay on the safe side, but nothing replaces real error checking.

The tool name is VSTriage, but it may be changed sooner or later, as it no longer reflects the real purpose. I simply have started to like it.

In the era of multi-GB strange-framework-based apps, I feel especially satisfied with the exe size. But it may be only me.

I hope you will never have to use it :)

And here comes the magic if you want to understand the code and not only use it: [![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/gtworek/VolatileDataCollector)
