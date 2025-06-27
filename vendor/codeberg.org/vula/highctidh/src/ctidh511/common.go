package ctidh511

/*
 #cgo CFLAGS: -DBITS=511 -DCGONUTS -O2
 #cgo LDFLAGS:
 #cgo linux CFLAGS: -DBITS=511 -DGETRANDOM -DCGONUTS -Wformat -Werror=format-security -D_FORTIFY_SOURCE=2 -fstack-protector-all -fpie -fPIC -O2
 #cgo linux LDFLAGS: -Wl,-z,noexecstack -Wl,-z,relro
 #cgo windows CFLAGS: -D__Windows__ -DHIGHCTIDH_PORTABLE=1

 // The following should work as native builds and as cross compiled builds.
 // Example cross compile build lines are provided as examples.

 // CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build -v
 #cgo arm64 CFLAGS: -DPLATFORM=aarch64 -DPLATFORM_SIZE=64 -DHIGHCTIDH_PORTABLE=1

 // CC=clang CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -v
 #cgo darwin/arm64 CFLAGS: -DPLATFORM=aarch64 -DPLATFORM_SIZE=64 -D__ARM64__ -D__Darwin__ -DGETRANDOM -DHIGHCTIDH_PORTABLE=1

 // export CGO_CFLAGS_ALLOW="-fforce-enable-int128";
 // CC=clang CGO_ENABLED=1 GOOS=linux GOARCH=arm ARMVER=7  go build
 #cgo arm CFLAGS: -DPLATFORM=arm -DPLATFORM_SIZE=32 -D__ARM32__ -DHIGHCTIDH_PORTABLE=1

 // CC=clang CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -v
 #cgo darwin/amd64 CFLAGS: -DPLATFORM=x86_64 -DPLATFORM_SIZE=64 -D__x86_64__ -march=native -mtune=native -D__Darwin__ -DGETRANDOM -DHIGHCTIDH_PORTABLE=1

 // Generic flags for amd64
 #cgo amd64 CFLAGS: -DPLATFORM=x86_64 -DPLATFORM_SIZE=64 -D__x86_64__ -fpie -fPIC -DHIGHCTIDH_PORTABLE=1

 // CC=gcc CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -v
 #cgo linux/amd64 CFLAGS: -DPLATFORM=x86_64 -DPLATFORM_SIZE=64 -march=native -mtune=native -D__x86_64__ -fpie -fPIC -DHIGHCTIDH_PORTABLE=1

 // CC=??? CGO_ENABLED=1 GOOS=windows GOARCH=arm64 go build
 #cgo windows/arm64 CFLAGS: -DPLATFORM=arm64 -DPLATFORM_SIZE=64 -D__Windows__ -DHIGHCTIDH_PORTABLE=1

 // CC=/usr/bin/x86_64-w64-mingw32-gcc CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go build
 #cgo windows/amd64 CFLAGS: -DPLATFORM=x86_64 -DPLATFORM_SIZE=64 -DCGONUTS -D__Windows__ -DHIGHCTIDH_PORTABLE=1

 // CC=powerpc64le-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=ppc64le go build -v
 #cgo ppc64le CFLAGS: -DPLATFORM=ppc64le -DPLATFORM_SIZE=64 -DHIGHCTIDH_PORTABLE=1

 // CC=powerpc64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=ppc64 go build -v
 #cgo ppc64 CFLAGS: -DPLATFORM=ppc64 -DPLATFORM_SIZE=64 -DHIGHCTIDH_PORTABLE=1

 // CC=riscv64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=riscv64 go build -v
 #cgo riscv64 CFLAGS: -DPLATFORM=riscv64 -D__riscv -DPLATFORM_SIZE=64 -DHIGHCTIDH_PORTABLE=1

 // CC=gcc CGO_ENABLED=1 GOOS=solaris GOARCH=amd64 go build
 #cgo solaris/amd64 CFLAGS: -m64 -mimpure-text -Wno-attributes -DPLATFORM=i86pc -DPLATFORM_SIZE=64 -D__sun -D__i86pc__ -DHIGHCTIDH_PORTABLE=0

 // CC=gcc CGO_ENABLED=1 GOOS=solaris GOARCH=sparc64 go build
 #cgo solaris/sparc64 CFLAGS: -m64 -DPLATFORM=sun4v -DPLATFORM_SIZE=64 -D__sun -DHIGHCTIDH_PORTABLE=1

 // CC=s390x-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=s390x go build -v
 #cgo s390x CFLAGS: -DPLATFORM=s390x -DPLATFORM_SIZE=64 -DHIGHCTIDH_PORTABLE=1

 // CC=mips64-linux-gnuabi64-gcc CGO_ENABLED=1 GOOS=linux GOARCH=mips64  go build
 // With clang, -fforce-enable-int128 must be added to the CFLAGS
 #cgo mips64 CFLAGS: -DPLATFORM=mips64 -DPLATFORM_SIZE=64 -DHIGHCTIDH_PORTABLE=1

 // CC=mips64-linux-gnuabi64-gcc CGO_ENABLED=1 GOOS=linux GOARCH=mips64  go build
 // With clang, -fforce-enable-int128 must be added to the CFLAGS
 #cgo mips64le CFLAGS: -DPLATFORM=mips64le -DPLATFORM_SIZE=64 -DHIGHCTIDH_PORTABLE=1

 // CC=mipsel-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=mipsle  go build
 // With clang, -fforce-enable-int128 must be added to the CFLAGS
 #cgo mipsle CFLAGS: -DPLATFORM=mipsle -DPLATFORM_SIZE=32 -DHIGHCTIDH_PORTABLE=1

 // CC=mips-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=mips  go build
 // With clang, -fforce-enable-int128 must be added to the CFLAGS
 #cgo mips CFLAGS: -DPLATFORM=mips -DPLATFORM_SIZE=32 -DHIGHCTIDH_PORTABLE=1

 // CGO_CFLAGS_ALLOW="-fforce-enable-int128";
 // CC=clang CGO_ENABLED=1 GOOS=linux GOARCH=386  go build
 #cgo 386 CFLAGS: -DPLATFORM=i386 -DPLATFORM_SIZE=32 -fforce-enable-int128 -D__i386__ -DHIGHCTIDH_PORTABLE=1

 // The following should work as native builds with clang:

 #cgo loong64 CFLAGS: -DPLATFORM=loongarch64 -DPLATFORM_SIZE=64 -march=native -mtune=native -DHIGHCTIDH_PORTABLE=1

 #include "binding511.h"
*/
import "C"
import (
	"fmt"
	"io"
	"unsafe"

	gopointer "github.com/mattn/go-pointer"
)

// This function wraps go_fillrandom, so we can emulate the calls from the
// C library and test the results
func test_go_fillrandom(context unsafe.Pointer, outptr []byte) {
	highctidh_511_go_fillrandom(context, unsafe.Pointer(&outptr[0]), C.size_t(len(outptr)))
}

// This is called from the C library, DO NOT CHANGE THE FUNCTION INTERFACE
//
//export highctidh_511_go_fillrandom
func highctidh_511_go_fillrandom(context unsafe.Pointer, outptr unsafe.Pointer, outsz C.size_t) {
	rng := gopointer.Restore(context).(io.Reader)
	buf := make([]byte, outsz)
	count, err := rng.Read(buf)
	if err != nil {
		panic(err)
	}
	if count != int(outsz) {
		panic("rng fail")
	}
	for i := 0; i < int(outsz); i++ {
		p := unsafe.Pointer(uintptr(outptr) + uintptr(i))
		*(*uint8)(p) = uint8(buf[i])
	}
}

// Name returns the string naming of the current
// CTIDH that this binding is being used with;
// Valid values are:
//
// CTIDH-511, CTIDH-512, CTIDH-1024 and, CTIDH-2048.
func Name() string {
	return fmt.Sprintf("CTIDH-%d", C.BITS)
}

func validateBitSize(bits int) {
	switch bits {
	case 511:
	case 512:
	case 1024:
	case 2048:
	default:
		panic("CTIDH/cgo: BITS must be 511 or 512 or 1024 or 2048")
	}
}
