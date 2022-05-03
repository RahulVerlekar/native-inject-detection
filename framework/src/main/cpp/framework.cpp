#include <stdio.h>
#include <jni.h>
#include <string.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <android/log.h>
#include <unistd.h>
#include <errno.h>
#include <string>

#define APPNAME "FridaDetectionTest"
#define MAX_LINE 512

static char keyword[] = "libfrida";

int find_mem_string(unsigned long, unsigned long, char*, unsigned int);
int scan_executable_segments(char *);
int read_one_line(int fd, char *buf, unsigned int max_len);

extern "C"
JNIEXPORT jstring JNICALL Java_com_numadic_framework_NuSecurityLib_detect(JNIEnv *env, jobject thisObj) {

    struct sockaddr_in sa;

    int sock;

    int fd;
    char map[MAX_LINE];
    int num_found;

    /*
     * 1: Port 27042 is checked
     * We also provide our own implementations of open() and read() - see syscall.S
     */

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(27042);
    inet_aton("127.0.0.1", &(sa.sin_addr));

    sock = socket(AF_INET , SOCK_STREAM , 0);

    if (connect(sock , (struct sockaddr*)&sa , sizeof sa) != -1) {
        return (*env).NewStringUTF("Frida Detected Using PORT");
    }

    /*
     * 2: Scan memory for treacherous strings!
     * We also provide our own implementations of open() and read() - see syscall.S
     */

    num_found = 0;

    if ((fd = openat(AT_FDCWD, "/proc/self/maps", O_RDONLY, 0)) >= 0) {


        while ((read_one_line(fd, map, MAX_LINE)) > 0) {
//            __android_log_print(ANDROID_LOG_VERBOSE, APPNAME,  "PROC11: %s", map);
            if (scan_executable_segments(map) == 1) {
                num_found++;
            }
        }

        if (num_found > 1) {
            __android_log_print(ANDROID_LOG_VERBOSE, APPNAME,  "FRIDA DETECTED [2] - suspect string found in memory!");
            return (*env).NewStringUTF("Frida Detected Using PROC");
        }

    } else {
        __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "Error opening /proc/self/maps. That's usually a bad sign.");
        return (*env).NewStringUTF("Frida Might be Detected(System Tempered)");
    }
    return (*env).NewStringUTF("Frida Not Detected");
}

extern "C"
JNIEXPORT jint JNICALL Java_com_numadic_framework_NuSecurityLib_hasInjection(
        JNIEnv* env,
        jobject /* this */) {

    struct sockaddr_in sa;

    int sock;

    int fd;
    char map[MAX_LINE];
    char res[7];
    int num_found;
    int ret;
    int i = 0;

    /*
     * 1: Port 27042 is checked
     * We also provide our own implementations of open() and read() - see syscall.S
     */

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(27042);
    inet_aton("127.0.0.1", &(sa.sin_addr));

    sock = socket(AF_INET , SOCK_STREAM , 0);

    if (connect(sock , (struct sockaddr*)&sa , sizeof sa) != -1) {
        return 1;
    }

    /*
     * 2: Scan memory for treacherous strings!
     * We also provide our own implementations of open() and read() - see syscall.S
     */

    num_found = 0;

    if ((fd = openat(AT_FDCWD, "/proc/self/maps", O_RDONLY, 0)) >= 0) {

        __android_log_print(ANDROID_LOG_VERBOSE, APPNAME,  "HEre after loop");
        while ((read_one_line(fd, map, MAX_LINE)) > 0) {
            __android_log_print(ANDROID_LOG_VERBOSE, APPNAME,  "PROC11 at %d: %s",i++, map);

            if (scan_executable_segments(map) == 1) {
                num_found++;
            }
        }

        if (num_found > 1) {
            __android_log_print(ANDROID_LOG_VERBOSE, APPNAME,  "FRIDA DETECTED [2] - suspect string found in memory!");
            return 1;
        }

    } else {
        __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "Error opening /proc/self/maps. That's usually a bad sign.");
        return 1;
    }

    return 0;
}


int find_mem_string(unsigned long start, unsigned long end, char *bytes, unsigned int len) {
    return 0;
    char *pmem = (char*)start;
    int matched = 0;

    while ((unsigned long)pmem < (end - len)) {

        if(*pmem == bytes[0]) {

            matched = 1;
            char *p = pmem + 1;

            while (*p == bytes[matched] && (unsigned long)p < end) {
                matched ++;
                p ++;
            }

            if (matched >= len) {
                return 1;
            }
        }

        pmem ++;

    }
    return 0;
}

int scan_executable_segments(char * map) {
    char buf[512];
    unsigned long start, end;

    sscanf(map, "%lx-%lx %s", &start, &end, buf);

    if (buf[2] == 'x') {
        return (find_mem_string(start, end, (char*)keyword, 8) == 1);
    } else {
        return 0;
    }
}

int read_one_line(int fd, char *buf, unsigned int max_len) {
    char b;
    ssize_t ret;
    ssize_t bytes_read = 0;

    memset(buf, 0, max_len);

    do {
        ret = read(fd, &b, 1);

        if (ret != 1) {
            if (bytes_read == 0) {
                // error or EOF
                return -1;
            } else {
                return bytes_read;
            }
        }

        if (b == '\n') {
            return bytes_read;
        }

        *(buf++) = b;
        bytes_read += 1;

    } while (bytes_read < max_len - 1);

    return bytes_read;
}

extern "C" long __set_errno_internal(int n) {
    errno = n;
    return -1;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_numadic_framework_NuSecurityLib_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}