Option Explicit
' 开机自启：静默拉起 Qoder Hub 网关（隐藏窗口，无控制台）
' 用法：双击，或由启动文件夹快捷方式 / 计划任务调用。
'
' 设计要点：
'   1) 单实例：已在运行则不重复启动（避免端口冲突）。
'   2) 隐藏：窗口模式 0，不开控制台。
'   3) 清代理：qoder_accounts 明确要求直连上游，进程级 *_PROXY 会
'      把国际/国内出口拖进代理故障域；这里主动清除，继承给子进程。
'   4) 留日志：网关日志走 stderr，重定向到 server.err.log 便于排查。
Dim objShell, objFSO, objWMI, colProc, strDir, strPy, strCmd

Set objShell = CreateObject("WScript.Shell")
Set objFSO   = CreateObject("Scripting.FileSystemObject")

strDir = objFSO.GetParentFolderName(WScript.ScriptFullName)
objShell.CurrentDirectory = strDir

' 单实例：检查是否已有本项目的 qoder_proxy.py 在跑
Set objWMI = GetObject("winmgmts:\\.\root\cimv2")
Set colProc = objWMI.ExecQuery("Select * from Win32_Process Where Name = 'python.exe' or Name = 'pythonw.exe'")
Dim p, cmd, running
running = False
For Each p In colProc
    cmd = ""
    On Error Resume Next
    cmd = p.CommandLine
    On Error Goto 0
    If Not IsNull(cmd) Then
        If InStr(LCase(cmd), "qoder_proxy.py") > 0 Then running = True
    End If
Next

If running Then
    WScript.Quit 0
End If

' 清代理（进程级，子进程继承）
Dim env
Set env = objShell.Environment("PROCESS")
env.Remove "HTTP_PROXY"
env.Remove "HTTPS_PROXY"
env.Remove "ALL_PROXY"
env.Remove "http_proxy"
env.Remove "https_proxy"
env.Remove "all_proxy"

' 解析 python：优先项目内捆绑运行时，其次 PATH
strPy = "pythonw.exe"
If objFSO.FileExists(strDir & "\python\pythonw.exe") Then
    strPy = """" & strDir & "\python\pythonw.exe"""
ElseIf objFSO.FileExists(strDir & "\python\python.exe") Then
    strPy = """" & strDir & "\python\python.exe"""
End If

strCmd = "cmd.exe /c cd /d """ & strDir & """ && """ & strPy & """ qoder_proxy.py --port 8790 >> """ & strDir & "\server.out.log"" 2>> """ & strDir & "\server.err.log"""
objShell.Run strCmd, 0, False
