#ifndef _CGO_H
#define _CGO_H

#ifdef CGONUTS

#if BITS == 511
#include "binding511.h"
#endif // BITS == 511

#if BITS == 512
#include "binding512.h"
#endif // BITS == 512

#if BITS == 1024
#include "binding1024.h"
#endif // BITS == 1024

#if BITS == 2048
#include "binding2048.h"
#endif // BITS == 2048

#endif // CGONUTS

#endif // _CGO_H
