# How To Use
Include manualmap.cs in your C# project (win forms, wpf, etc.) <br>
Import the ManualMapApi namespace <br>
Use the function "ManualMap" like so: <br>

// ManualMap(Process proc, string filepath) <br>
MapInject.ManualMap(Process.GetProcessesByName("FunGameToHack")[0], "C:/.../myfundll.dll"); <br>

This will inject your DLL or binary file safely without any ties to the module <br>
whatsoever (it is virtually allocated into the process). It will use LoadLibrary for dependencies but that's required. Overall, it's more effective and less detectable than injecting a dll the traditional way (with just LoadLibrary)

That being said, some games may detect virtually allocated memory with PAGE_EXECUTE privileges (this would apply even more-so to using LoadLibrary)<br>

This API only allows injection of x86 dlls into x86 processes.

