# QRCode Terminal

[![Build Status](https://github.com/katzenpost/qrterminal/actions/workflows/build.yml/badge.svg)](https://github.com/katzenpost/qrterminal/actions/workflows/build.yml)

A golang library for generating QR codes in the terminal.

Originally this was a port of the [NodeJS version](https://github.com/gtanner/qrcode-terminal). Recently it's been updated to allow for smaller code generation using ASCII 'half blocks'

## Example
Full size ASCII block QR Code:  
<img src="https://user-images.githubusercontent.com/2868/37992336-0ba06b56-31d1-11e8-9d32-5c6bb008dc74.png" alt="alt text" width="225" height="225">

Smaller 'half blocks' in the terminal:  
<img src="https://user-images.githubusercontent.com/2868/37992371-243d4238-31d1-11e8-92f8-e34a794b21af.png" alt="alt text" width="225" height="225">

## Install

For command line usage [see below](https://github.com/katzenpost/qrterminal#command-line), or grab the binary from the [releases page](https://github.com/katzenpost/qrterminal/releases)

As a library in an application

`go get github.com/katzenpost/qrterminal/v3`

## Usage

```go
import (
    "github.com/katzenpost/qrterminal/v3"
    "os"
    )

func main() {
  // Generate a 'dense' qrcode with the 'Low' level error correction and write it to Stdout
  qrterminal.Generate("https://github.com/katzenpost/qrterminal", qrterminal.L, os.Stdout)
}
```

### Binary Data Support

qrterminal now supports encoding binary data directly without string conversion:

```go
import (
    "github.com/katzenpost/qrterminal/v3"
    "os"
    )

func main() {
  // Generate a QR code from binary data
  binaryData := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}
  qrterminal.GenerateBinary(binaryData, qrterminal.L, os.Stdout)
}
```

### More complicated

Large Inverted barcode with medium redundancy and a 1 pixel border
```go
import (
    "github.com/katzenpost/qrterminal/v3"
    "os"
    )

func main() {
  config := qrterminal.Config{
      Level: qrterminal.M,
      Writer: os.Stdout,
      BlackChar: qrterminal.WHITE,
      WhiteChar: qrterminal.BLACK,
      QuietZone: 1,
  }
  qrterminal.GenerateWithConfig("https://github.com/katzenpost/qrterminal", config)
}
```

HalfBlock barcode with medium redundancy
```go
import (
    "github.com/katzenpost/qrterminal/v3"
    "os"
    )

func main() {
  config := qrterminal.Config{
      HalfBlocks: true,
      Level: qrterminal.M,
      Writer: os.Stdout,
  }
  qrterminal.GenerateWithConfig("https://github.com/katzenpost/qrterminal", config)
}
```

Binary data with custom configuration
```go
import (
    "github.com/katzenpost/qrterminal/v3"
    "os"
    )

func main() {
  binaryData := []byte{0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x00, 0xFF}
  config := qrterminal.Config{
      Level: qrterminal.H,
      Writer: os.Stdout,
      HalfBlocks: true,
      QuietZone: 1,
  }
  qrterminal.GenerateBinaryWithConfig(binaryData, config)
}
```


## Command Line

#### Installation

OSX: `brew install mdp/tap/qrterminal`

Others: Download from the [releases page](https://github.com/katzenpost/qrterminal/releases)

Source: `go install github.com/katzenpost/qrterminal/v3/cmd/qrterminal@latest`

Docker: `docker pull ghcr.io/mdp/qrterminal:latest`

#### Usage

Print out a basic QR code in your terminal:
`qrterminal https://github.com/katzenpost/qrterminal`

Using 'medium' error correction:
`qrterminal https://github.com/katzenpost/qrterminal -l M`

Or just use Docker: `docker run --rm ghcr.io/mdp/qrterminal:latest 'https://github.com/katzenpost/qrterminal'`

You can also pipe text via stdin

`cat wireguard_peer.conf | qrterminal`

or

`cat wireguard_peer.conf | docker run --rm -i ghcr.io/mdp/qrterminal:latest`

For binary data, use the `-b` flag:

`cat binary_file.bin | qrterminal -b`

This preserves the exact byte values in the QR code without any string conversion.


### Contributors/Credits:

- [Mark Percival](https://github.com/mdp)
- [Matthew Kennerly](https://github.com/mtkennerly)  
- [Viric](https://github.com/viric)  
- [WindomZ](https://github.com/WindomZ)  
- [mattn](https://github.com/mattn)  
