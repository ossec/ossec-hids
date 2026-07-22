#ifndef WIN32
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#include "shared.h"

#ifdef LIBOPENSSL_ENABLED
#include <openssl/rand.h>
#include <openssl/opensslv.h>
#endif

/* Cap how long we hold the entropy FD mutex waiting on /dev/random. */
#ifndef RANDOMBYTES_READ_TIMEOUT_MS
#define RANDOMBYTES_READ_TIMEOUT_MS 5000
#endif


int randombytes_try(void *ptr, size_t length)
{
#ifdef WIN32
    static HCRYPTPROV prov = 0;
    static CRITICAL_SECTION prov_lock;
    static volatile LONG lock_ready = 0;
    int ok;

    /* One-time CRITICAL_SECTION init without races. */
    if (lock_ready != 2) {
        if (InterlockedCompareExchange(&lock_ready, 1, 0) == 0) {
            InitializeCriticalSection(&prov_lock);
            InterlockedExchange(&lock_ready, 2);
        } else {
            while (InterlockedCompareExchange(&lock_ready, 2, 2) != 2) {
                Sleep(1);
            }
        }
    }

    EnterCriticalSection(&prov_lock);

    /* CRYPT_VERIFYCONTEXT: ephemeral randomness, no key container required.
     * Avoids NTE_BAD_KEYSET on accounts without a default container.
     */
    if (prov == 0) {
        if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            LeaveCriticalSection(&prov_lock);
            return 0;
        }
    }

    ok = CryptGenRandom(prov, (DWORD)length, ptr) ? 1 : 0;
    LeaveCriticalSection(&prov_lock);
    return ok;
#elif defined(__OpenBSD__)
    /* LibreSSL RAND_bytes used arc4random; keep that path so chroot never
     * depends on /dev/urandom device nodes inside the jail.
     */
    if (length > 0 && ptr != NULL) {
        arc4random_buf(ptr, length);
    }
    return 1;
#else
    static int fh = -1;
    static pthread_mutex_t rb_fh_mutex = PTHREAD_MUTEX_INITIALIZER;
    unsigned char *p = (unsigned char *)ptr;
    size_t remaining = length;

    /* Keep the entropy FD open across chroot: open once before Privsep_Chroot
     * (via srandom_init), then reuse the FD after jail. Re-opening /dev/urandom
     * by path after chroot fails on platforms without getrandom() (e.g. AIX).
     * Mutex covers open/read/close so remoted/agent worker threads cannot race
     * error-recovery close/reset against concurrent readers. poll() bounds how
     * long a starved /dev/random can hold that lock.
     */
    pthread_mutex_lock(&rb_fh_mutex);

    if (fh < 0) {
        fh = open("/dev/urandom", O_RDONLY);
        if (fh < 0) {
            fh = open("/dev/random", O_RDONLY);
        }
    }

    if (fh < 0) {
        pthread_mutex_unlock(&rb_fh_mutex);
        return 0;
    }

    while (remaining > 0) {
        struct pollfd pfd;
        int pret;
        ssize_t ret;

        pfd.fd = fh;
        pfd.events = POLLIN;
        pret = poll(&pfd, 1, RANDOMBYTES_READ_TIMEOUT_MS);
        if (pret == 0) {
            close(fh);
            fh = -1;
            pthread_mutex_unlock(&rb_fh_mutex);
            return 0;
        }
        if (pret < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fh);
            fh = -1;
            pthread_mutex_unlock(&rb_fh_mutex);
            return 0;
        }

        ret = read(fh, p, remaining);

        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fh);
            fh = -1;
            pthread_mutex_unlock(&rb_fh_mutex);
            return 0;
        }
        if (ret == 0) {
            /* Unexpected EOF on a random device. */
            close(fh);
            fh = -1;
            pthread_mutex_unlock(&rb_fh_mutex);
            return 0;
        }

        p += (size_t)ret;
        remaining -= (size_t)ret;
    }

    pthread_mutex_unlock(&rb_fh_mutex);
    return 1;
#endif
}

void randombytes(void *ptr, size_t length)
{
    if (!randombytes_try(ptr, length)) {
        ErrorExit("%s: ERROR: randombytes failed for all possible methods for accessing random data", __local_name);
    }
}

void srandom_init(void)
{
#ifndef WIN32
#ifdef __OpenBSD__
    srandomdev();
#else
    unsigned int seed;
    randombytes(&seed, sizeof seed);
    srandom(seed);
#endif /* !__OpenBSD__ */
#ifdef LIBOPENSSL_ENABLED
    /* Seed OpenSSL before chroot so TLS/authd do not re-open /dev/urandom
     * by path inside the jail. Keep device FDs open across reseed on 1.1.1+.
     */
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    RAND_keep_random_devices_open(1);
#endif
    if (RAND_poll() != 1 || RAND_status() != 1) {
        merror("%s: ERROR: OpenSSL RNG failed to seed before chroot", __local_name);
    }
#endif /* LIBOPENSSL_ENABLED */
#endif /* !WIN32 */
}
