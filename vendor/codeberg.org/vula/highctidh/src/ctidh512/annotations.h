#ifndef ANNOTATIONS_H
#define ANNOTATIONS_H

/*
 * Denote that the first argument is a write-only pointer.
 */
#if defined(__GNUC__) && !defined(__clang__) && !defined(__INTEL_COMPILER)
#define ANNOTATIONS_H_ONLY_GCC(x) x
#else
#define ANNOTATIONS_H_ONLY_GCC(x)
#endif

#define ATTR_INITIALIZE_1st			\
	ANNOTATIONS_H_ONLY_GCC(__attribute__((access(write_only,1)))) \
	__attribute__((nonnull(1)))

#endif /* ANNOTATIONS_H */
