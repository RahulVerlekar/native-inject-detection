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

#define APPNAME "FridaDetectionTest"
#define MAX_LINE 512

//extern "C" int my_openat(int, const char*, int, int);
//extern "C" int my_read(int, void*, int);

static char keyword[] = "libfrida";

int find_mem_string(unsigned long, unsigned long, char*, unsigned int);
int scan_executable_segments(char *);
int read_one_line(int fd, char *buf, unsigned int max_len);

void *detect_frida_loop(void *) {

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    inet_aton("127.0.0.1", &(sa.sin_addr));

    int sock;

    int fd;
    char map[MAX_LINE];
    char res[7];
    int num_found;
    int ret;
    int i;

    while (1) {

        /*
         * 1: Frida Server Detection.
         *

        for(i = 0 ; i <= 65535 ; i++) {

            sock = socket(AF_INET , SOCK_STREAM , 0);
            sa.sin_port = htons(i);

            if (connect(sock , (struct sockaddr*)&sa , sizeof sa) != -1) {
                memset(res, 0 , 7);

                send(sock, "\x00", 1, NULL);
                send(sock, "AUTH\r\n", 6, NULL);

                usleep(100); // Give it some time to answer

                if ((ret = recv(sock, res, 6, MSG_DONTWAIT)) != -1) {
                    if (strcmp(res, "REJECT") == 0) {
                        __android_log_print(ANDROID_LOG_VERBOSE, APPNAME,  "FRIDA DETECTED [1] - frida server running on port %d!", i);
                    }
                }
            }

            close(sock);
        }*/

        /*
         * 2: Scan memory for treacherous strings!
         * We also provide our own implementations of open() and read() - see syscall.S
         */

        num_found = 0;

        if ((fd = openat(AT_FDCWD, "/proc/self/maps", O_RDONLY, 0)) >= 0) {


            while ((read_one_line(fd, map, MAX_LINE)) > 0) {
                if (scan_executable_segments(map) == 1) {
                    num_found++;
                }
            }

            if (num_found > 1) {
                __android_log_print(ANDROID_LOG_VERBOSE, APPNAME,  "FRIDA DETECTED [2] - suspect string found in memory!");
            }

        } else {
            __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "Error opening /proc/self/maps. That's usually a bad sign.");

        }

        sleep(3);
    }
}

/*
 * public native void init();
 */

extern "C"
JNIEXPORT void JNICALL Java_sg_vantagepoint_antifrida_MainActivity_init(JNIEnv *env, jobject thisObj) {

    pthread_t t;

    pthread_create(&t, NULL, detect_frida_loop, (void *)NULL);

}


extern "C"
JNIEXPORT jstring JNICALL Java_sg_vantagepoint_antifrida_MainActivity_detect(JNIEnv *env, jobject thisObj) {

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    inet_aton("127.0.0.1", &(sa.sin_addr));

    int sock;

    int fd;
    char map[MAX_LINE];
    char res[7];
    int num_found;
    int ret;
    int i;
/*
         * 1: Frida Server Detection.
         */
    /*__android_log_print(ANDROID_LOG_VERBOSE, APPNAME,  "Started Scanning");
    for(i = 0 ; i <= 65535 ; i++) {
        __android_log_print(ANDROID_LOG_VERBOSE, APPNAME,  "Scanning port number %d!", i);

        sock = socket(AF_INET , SOCK_STREAM , 0);
        sa.sin_port = htons(i);

        if (connect(sock , (struct sockaddr*)&sa , sizeof sa) != -1) {
            memset(res, 0 , 7);

            send(sock, "\x00", 1, NULL);
            send(sock, "AUTH\r\n", 6, NULL);

            usleep(100); // Give it some time to answer

            if ((ret = recv(sock, res, 6, MSG_DONTWAIT)) != -1) {
                if (strcmp(res, "REJECT") == 0) {
                    __android_log_print(ANDROID_LOG_VERBOSE, APPNAME,  "FRIDA DETECTED [1] - frida server running on port %d!", i);
                    return (*env).NewStringUTF("Frida Detected");
                }
            }
        }

        close(sock);
    }

    /*
     * 2: Scan memory for treacherous strings!
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

    num_found = 0;

    if ((fd = openat(AT_FDCWD, "/proc/self/maps", O_RDONLY, 0)) >= 0) {


        while ((read_one_line(fd, map, MAX_LINE)) > 0) {
            __android_log_print(ANDROID_LOG_VERBOSE, APPNAME,  "PROC11: %s", map);
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

void print_string(unsigned long start, unsigned long end) {
    char *pmem = (char*)start;
    int count = 0;
    while((unsigned long)pmem < end) {
        pmem++;
        count++;
    }
    if (count > 0) {
        int i = 0;
        char name[count];
        pmem = (char*)start;
        while (i<count) {
            name[i] = *pmem;
            i++;
            pmem++;
        }
        __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "The Process is: %s", name);
    }
}

int find_mem_string(unsigned long start, unsigned long end, char *bytes, unsigned int len) {

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

// Used by syscall.S

extern "C" long __set_errno_internal(int n) {
    errno = n;
    return -1;
}
