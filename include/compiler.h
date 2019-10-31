/*
************************************************************************************************************************
*                                                     QUARK LIBRARY
*                                                 The basic c modules
*
*                                               (c) Copyright 2019-20XX; ShaaXi, Xi'an
*                           All rights reserved.  Protected by international copyright laws.
*
*     FILE: compiler.h
*       BY: DOER
*  VERSION: V0.0.1
*  
*
* LICENSING TERMS:
* ---------------
*           The MIT License (MIT)
*
*           Copyright © 2019 <copyright holders>
*
*           Permission is hereby granted, free of charge, to any person obtaining a copy of this software
*           and associated documentation files (the “Software”), to deal in the Software without restriction,
*           including without limitation the rights to use, copy, modify, merge, publish, distribute, 
*           sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
*           furnished to do so, subject to the following conditions:
*
*           The above copyright notice and this permission notice shall be included in all copies or
*           substantial portions of the Software.
*
*           THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING 
*           BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
*           NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, 
*           DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
*           OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*
*
************************************************************************************************************************
* Note(s) : (1) the following compiler has been tested, so your compiler should be here and its version is higher:
*
*               (a) gcc-7.3
*               (b) clang-6.0
************************************************************************************************************************
*/


#ifndef __COMPILER_H__
#define __COMPILER_H__

#include <stddef.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <stdint.h>

/*
************************************************************************************************************************
*                                                 INCLUDE HEADER FILES
************************************************************************************************************************
*/

#ifdef __cplusplus
extern "C" {
#endif


#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define __LOCAL(var, line) __ ## var ## line
#define _LOCAL(var, line) __LOCAL(var, line)
#define LOCAL(var) _LOCAL(var, __LINE__)

#define container_of(ptr, type, member) ({			                           \
	const typeof(((type *)0)->member) *__mptr = (ptr);	                       \
	(type *)((char *)__mptr - offsetof(type, member)); })

#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

#define __packed __attribute((packed))

#define asmlinkage  __attribute__((regparm(0)))

#define __printf(a, b) __attribute__((format(printf, a, b)))

/* Force a compilation error if the condition is true */
#define BUILD_BUG_ON(condition) ((void)sizeof(struct { int: -!!(condition); }))

#define __must_check            __attribute__((warn_unused_result))

#ifdef HAVE_SYS_SIGNALFD_H
#include <sys/signalfd.h>
#else
#define SFD_NONBLOCK	(04000)
struct signalfd_siginfo {
	uint32_t ssi_signo;
	int32_t ssi_errno;
	int32_t ssi_code;
	uint32_t ssi_pid;
	uint32_t ssi_uid;
	int32_t ssi_fd;
	uint32_t ssi_tid;
	uint32_t ssi_band;
	uint32_t ssi_overrun;
	uint32_t ssi_trapno;
	int32_t ssi_status;
	int32_t ssi_int;
	uint64_t ssi_ptr;
	uint64_t ssi_utime;
	uint64_t ssi_stime;
	uint64_t ssi_addr;
	uint16_t ssi_addr_lsb;
	uint8_t __pad[46];
};

static inline int signalfd(int __fd, const sigset_t *__mask, int __flags)
{
	return syscall(__NR_signalfd4, __fd, __mask, _NSIG / 8, __flags);
}
#endif

#ifdef HAVE_SYS_EVENTFD_H
#include <sys/eventfd.h>
#else
#define EFD_SEMAPHORE	(1)
#define EFD_NONBLOCK	(04000)
#define eventfd_t	uint64_t
static inline int eventfd_write(int fd, eventfd_t value)
{
	return write(fd, &value, sizeof(eventfd_t)) !=
			sizeof(eventfd_t) ? -1 : 0;
}

static inline int eventfd_read(int fd, eventfd_t *value)
{
	return read(fd, value, sizeof(eventfd_t)) !=
			sizeof(eventfd_t) ? -1 : 0;
}

static inline int eventfd(unsigned int initval, int flags)
{
	return syscall(__NR_eventfd2, initval, flags);
}
#endif

#ifdef HAVE_SYS_TIMERFD_H
#include <sys/timerfd.h>
#else
#define TFD_NONBLOCK (04000)
static inline int timerfd_create(clockid_t __clock_id, int __flags)
{
	return syscall(__NR_timerfd_create, __clock_id, __flags);
}

static inline int timerfd_settime(int __ufd, int __flags,
		__const struct itimerspec *__utmr, struct itimerspec *__otmr)
{
	return syscall(__NR_timerfd_settime, __ufd, __flags, __utmr, __otmr);
}
#endif

#ifndef HAVE_FALLOCATE
static inline int fallocate(int fd, int mode, __off_t offset, __off_t len)
{
	return syscall(__NR_fallocate, fd, mode, offset, len);
}
#endif

#ifdef __x86_64__

#define X86_FEATURE_SSSE3	(4 * 32 + 9) /* Supplemental SSE-3 */
#define X86_FEATURE_OSXSAVE	(4 * 32 + 27) /* "" XSAVE enabled in the OS */
#define X86_FEATURE_AVX	(4 * 32 + 28) /* Advanced Vector Extensions */

#define XSTATE_FP	0x1
#define XSTATE_SSE	0x2
#define XSTATE_YMM	0x4

#define XCR_XFEATURE_ENABLED_MASK	0x00000000

static inline int cpu_has(int flag)
{
	uint32_t eax, ebx, ecx, edx;

	eax = (flag & 0x100) ? 7 :
		(flag & 0x20) ? 0x80000001 : 1;
	ecx = 0;

	asm volatile("cpuid"
		     : "+a" (eax), "=b" (ebx), "=d" (edx), "+c" (ecx));

	return ((flag & 0x100 ? ebx :
		 (flag & 0x80) ? ecx : edx) >> (flag & 31)) & 1;
}

static inline uint64_t xgetbv(uint32_t idx)
{
	uint32_t eax, edx;

	asm volatile(".byte 0x0f,0x01,0xd0" /* xgetbv */
		     : "=a" (eax), "=d" (edx)
		     : "c" (idx));
	return eax + ((uint64_t)edx << 32);
}

#define cpu_has_ssse3           cpu_has(X86_FEATURE_SSSE3)
#define cpu_has_avx		cpu_has(X86_FEATURE_AVX)
#define cpu_has_osxsave		cpu_has(X86_FEATURE_OSXSAVE)

#endif /* __x86_64__ */


#ifdef __cplusplus
}
#endif

#endif	/* __COMPILER_H__ */
