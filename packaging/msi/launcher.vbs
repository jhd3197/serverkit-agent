' ServerKit Agent launcher
'
' Why this exists: Windows SmartScreen silently terminates the unsigned
' serverkit-agent.exe when it is launched directly from Explorer / the
' Start menu / Search. Launching PowerShell or cmd from those same places
' works, because the SmartScreen reputation check applies to the *initial*
' user-clicked process, not its children.
'
' wscript.exe is signed by Microsoft and always trusted. By having the
' shortcut launch wscript with this script, the agent inherits a clean
' trust chain and starts reliably regardless of code-signing state.
'
' wscript runs without a console window, so there is no visible flash.

Option Explicit

Dim shell, fso, scriptPath, installDir, exePath, args, i

Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

scriptPath = WScript.ScriptFullName
installDir = fso.GetParentFolderName(scriptPath)
exePath = fso.BuildPath(installDir, "serverkit-agent.exe")

' Forward any arguments wscript was given (so e.g. --repair still works
' if a shortcut or another launcher passes flags through).
args = ""
If WScript.Arguments.Count > 0 Then
  For i = 0 To WScript.Arguments.Count - 1
    If args <> "" Then args = args & " "
    args = args & """" & WScript.Arguments(i) & """"
  Next
End If

If args = "" Then
  shell.Run """" & exePath & """", 0, False
Else
  shell.Run """" & exePath & """ " & args, 0, False
End If
