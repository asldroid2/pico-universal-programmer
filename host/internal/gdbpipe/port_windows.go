//go:build windows

package gdbpipe

import (
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

var (
	modKernel32         = syscall.NewLazyDLL("kernel32.dll")
	procGetCommState    = modKernel32.NewProc("GetCommState")
	procSetCommState    = modKernel32.NewProc("SetCommState")
	procSetCommTimeouts = modKernel32.NewProc("SetCommTimeouts")
)

type winDCB struct {
	DCBlength  uint32
	BaudRate   uint32
	Flags      uint32
	wReserved  uint16
	XonLim     uint16
	XoffLim    uint16
	ByteSize   byte
	Parity     byte
	StopBits   byte
	XonChar    byte
	XoffChar   byte
	ErrorChar  byte
	EofChar    byte
	EvtChar    byte
	wReserved1 uint16
}

type winCommTimeouts struct {
	ReadIntervalTimeout         uint32
	ReadTotalTimeoutMultiplier  uint32
	ReadTotalTimeoutConstant    uint32
	WriteTotalTimeoutMultiplier uint32
	WriteTotalTimeoutConstant   uint32
}

func openOSSerialPort(portPath string) (io.ReadWriteCloser, error) {
	p := strings.TrimSpace(portPath)
	if strings.HasPrefix(strings.ToUpper(p), "COM") && !strings.HasPrefix(p, `\\.\`) {
		p = `\\.\` + p
	}
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", p, err)
	}

	var dcb winDCB
	dcb.DCBlength = uint32(unsafe.Sizeof(dcb))
	r1, _, _ := procGetCommState.Call(f.Fd(), uintptr(unsafe.Pointer(&dcb)))
	if r1 != 0 {
		dcb.BaudRate = 115200
		dcb.ByteSize = 8
		dcb.Parity = 0
		dcb.StopBits = 0
		dcb.Flags = 0x00000001 // fBinary = 1
		_, _, _ = procSetCommState.Call(f.Fd(), uintptr(unsafe.Pointer(&dcb)))

		// Non-zero ReadIntervalTimeout returns immediately once a burst arrives while blocking until >=1 byte.
		to := winCommTimeouts{
			ReadIntervalTimeout: 10,
		}
		_, _, _ = procSetCommTimeouts.Call(f.Fd(), uintptr(unsafe.Pointer(&to)))
	}
	return f, nil
}
