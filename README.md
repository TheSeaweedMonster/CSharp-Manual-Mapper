# How To Use
Include manualmap.cs in your C# project (win forms, wpf, etc.) <br>
Import the ManualMapApi namespace <br>
Use the function "ManualMap" like so: <br>

// ManualMap(Process proc, string filepath) <br>
MapInject.ManualMap(Process.GetProcessesByName("FunGameToHack")[0], "C:/.../myfundll.dll"); <br>

This will inject your DLL or binary file safely without any ties to the module <br>
