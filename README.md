# MMINJ
Open-source Manual Map Injection for C# (All External)

# How To Use
Include manualmap.cs in your C# project (win forms, wpf, etc.) <br>
Import the ManualMapApi namespace <br>
Use the function "ManualMap" like so: <br>

// ManualMap(Process proc, string filepath) <br>
MapInject.ManualMap(Process.GetProcessesByName("FunGameToHack")[0], "C:/.../myfundll.dll"); <br>

This will inject your DLL or binary file safely  without any ties to the module <br>
whatsoever (it is virtually allocated into the process). So, it is far more effective and less detectable than traditional LoadLibrary methods.

That being said, some games might detect the presence of virtually allocated memory with PAGE_EXECUTE privileges (this would apply even more-so to using LoadLibrary)
