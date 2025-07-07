// Package csidh implements cSIDH key exchange, isogeny-based scheme
// resulting from the group action. Implementation uses only prime
// field of a size 512-bits and uses Ed some performance improvements
// by using twisted Edwards curves in the isogeny image curve
// computations. This work has been described by M. Meyer and S. Reith
// in the ia.cr/2018/782. Original cSIDH paper can be found in the
// ia.cr/2018/383.
//
// It is experimental implementation, not meant to be secure. Have fun!
//
package csidh
