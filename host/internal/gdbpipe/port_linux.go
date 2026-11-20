//go:build linux

package gdbpipe

import (
	"fmt"
	"io"
	"os"
	"syscall"
	"unsafe"
)

func openOSSerialPort(portPath string) (io.ReadWriteCloser, error) {
	f, err := os.OpenFile(portPath, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", portPath, err)
	}

	var tio syscall.Termios
	_, _, errno := syscall.Syscall6(
		syscall.SYS_IOCTL,
		f.Fd(),
		uintptr(syscall.TCGETS),
		uintptr(unsafe.Pointer(&tio)),
		0, 0, 0,
	)
	if errno == 0 {
		// Configure 8N1 raw mode (cfmakeraw) so Linux N_TTY never echoes or buffers GDB RSP packets.
		tio.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP |
			syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON | syscall.IXOFF
		tio.Oflag &^= syscall.OPOST
		tio.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
		tio.Cflag &^= syscall.CSIZE | syscall.PARENB
		tio.Cflag |= syscall.CS8 | syscall.CLOCAL | syscall.CREAD
		tio.Cc[syscall.VMIN] = 1
		tio.Cc[syscall.VTIME] = 0

		_, _, _ = syscall.Syscall6(
			syscall.SYS_IOCTL,
			f.Fd(),
			uintptr(syscall.TCSETS),
			uintptr(unsafe.Pointer(&tio)),
			0, 0, 0,
		)
	}
	return f, nil
}
