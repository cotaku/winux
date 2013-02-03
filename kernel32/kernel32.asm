.386
.model flat, stdcall
option casemap :none

.code
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
; dll 的入口函数
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
DllEntry	proc

		mov eax, 1
		ret

DllEntry	Endp
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
ExitProcess	proc	uExitCode

		mov ebx, uExitCode
		mov eax, 1
		int 80h

ExitProcess	endp
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
GetStdHandle	proc	nStdHandle

		mov eax, 1
		ret 4

GetStdHandle	endp
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
WriteConsoleA	proc	hConsoleOutput, lpBuffer, nNumberOfCharsToWrite, lpNumberOfCharsWritten, lpReserved

		pushad
		mov edx, nNumberOfCharsToWrite		; 参数三：字符串长度
		mov ecx, lpBuffer			; 参数二：要显示的字符串
		mov ebx, hConsoleOutput			; 参数一：文件描述符(stdout) 
		mov eax, 4
		int 80h
		mov eax, lpNumberOfCharsWritten
		mov edx, nNumberOfCharsToWrite
		mov [eax], edx
		popad
		mov eax, 1
		ret 20

WriteConsoleA	endp
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		End	DllEntry
