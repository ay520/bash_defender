/* get system boot time ,use unix time by wukong 2024.09.10 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <time.h>

#ifdef __linux__
#include <sys/sysinfo.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/sysctl.h>
#include <sys/time.h>
#else
#error "Unsupported platform"
#endif

static long unsigned int get_system_boot_time();

static long unsigned int get_system_boot_time()
{
#ifdef __linux__
    struct sysinfo info;
    if (sysinfo(&info) != 0) {
        fprintf(stderr, "Failed to get sysinfo, errno: %u, reason: %s\n", errno, strerror(errno));
        return -1;
    }
    return time(NULL) - info.uptime; // boot_time = current_time - uptime
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    // For macOS and BSD systems
    int mib[2];
    struct timeval tv;
    size_t len = sizeof(tv);

    mib[0] = CTL_KERN;
    mib[1] = KERN_BOOTTIME;

    if (sysctl(mib, 2, &tv, &len, NULL, 0) != 0) {
        fprintf(stderr, "Failed to get boot time, errno: %u, reason: %s\n", errno, strerror(errno));
        return -1;
    }
    return time(NULL) - tv.tv_sec; // boot_time = current_time - boot_time
#endif
}

/*

int main() {
    long unsigned int boot_time = get_system_boot_time();
    if (boot_time != (long unsigned int)-1) {
        printf("System boot time: %lu seconds ago\n", boot_time);
    }
    return 0;
}
*/