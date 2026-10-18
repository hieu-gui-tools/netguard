' Script tao Shortcut NetGuard ra Desktop voi quyen Administrator
Option Explicit

Dim WshShell, fso, currentDir, cmd

Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

currentDir = fso.GetParentFolderName(WScript.ScriptFullName)
WshShell.CurrentDirectory = currentDir

cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File " & Chr(34) & currentDir & "\create_shortcut.ps1" & Chr(34)
WshShell.Run cmd, 1, True

Set WshShell = Nothing
Set fso = Nothing
