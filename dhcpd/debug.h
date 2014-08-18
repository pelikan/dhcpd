#ifndef	EBUG_REFCOUNT
#define	REFCOUNT_DEBUG(a, b, c)	(void) 0
#else
#include <dlfcn.h>

/* Only works on SPARC, because the insns are fixed length of 4 bytes. */
/* Doesn't actually reliably work, half the symbol names aren't there. */

#define REFCOUNT_DEBUG(p, comment, cnt)	do {				\
	Dl_info __info;							\
	int __ret = 1;							\
	void *__ra;							\
	char *__p;							\
									\
	__p = __ra = __builtin_return_address(0);			\
	__p += 4;							\
	do {								\
		__p -= 4;						\
		__ret = dladdr(__p, &__info);				\
	} while (__ret && __p != (char *) __info.dli_saddr);		\
	log_warnx("%s: %p: %s: refcnt %d caller %p %s", __func__, (p),	\
	    (comment), (cnt),						\
	    __ra, __ret ? __info.dli_sname : "(not found)");		\
 } while (/* CONSTCOND */ 0)
#endif	/* EBUG_REFCOUNT */
