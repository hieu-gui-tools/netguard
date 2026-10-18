' NetGuard - VBS Launcher (Khoi chay voi quyen Administrator, khong hien console CMD)
Option Explicit

Dim ShellApp, fso, currentDir, pywPath, exePath, i, args

Set ShellApp = CreateObject("Shell.Application")
Set fso = CreateObject("Scripting.FileSystemObject")

currentDir = fso.GetParentFolderName(WScript.ScriptFullName)
exePath = currentDir & "\.venv\Scripts\netguard-gui.exe"
pywPath = currentDir & "\.venv\Scripts\pythonw.exe"

' Thu thap tham so dong lenh neu co
args = ""
For i = 0 To WScript.Arguments.Count - 1
    args = args & " " & Chr(34) & WScript.Arguments(i) & Chr(34)
Next

If fso.FileExists(exePath) Then
    ' Chay truc tiep netguard-gui.exe voi quyen Administrator qua ShellExecute (verb "runas")
    ShellApp.ShellExecute exePath, Trim(args), currentDir, "runas", 1
ElseIf fso.FileExists(pywPath) Then
    ' Fallback chay pythonw.exe voi quyen Administrator
    Dim pyArgs
    pyArgs = "-m netguard"
    If Trim(args) <> "" Then pyArgs = pyArgs & " " & Trim(args)
    ShellApp.ShellExecute pywPath, pyArgs, currentDir, "runas", 1
Else
    ' Fallback goi run.cmd voi quyen Administrator
    ShellApp.ShellExecute "cmd.exe", "/c " & Chr(34) & Chr(34) & currentDir & "\run.cmd" & Chr(34) & args & Chr(34), currentDir, "runas", 0
End If

Set ShellApp = Nothing
Set fso = Nothing
