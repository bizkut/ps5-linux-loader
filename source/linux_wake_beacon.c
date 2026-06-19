#include "config.h"
#include "linux_wake_beacon.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef ENABLE_LINUX_WAKE_BEACON
#define ENABLE_LINUX_WAKE_BEACON 1
#endif
#ifndef LINUX_WAKE_BEACON_TOKEN
#define LINUX_WAKE_BEACON_TOKEN "ps5-linux"
#endif
#ifndef LINUX_WAKE_BEACON_PORT
#define LINUX_WAKE_BEACON_PORT 9755
#endif
#ifndef LINUX_WAKE_BEACON_REPEATS
#define LINUX_WAKE_BEACON_REPEATS 3
#endif
#ifndef LINUX_WAKE_BEACON_INTERVAL_US
#define LINUX_WAKE_BEACON_INTERVAL_US 300000
#endif

int linux_wake_beacon_send(unsigned int firmware_version) {
#if ENABLE_LINUX_WAKE_BEACON
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    printf("[linux-wake] socket failed errno=%d\n", errno);
    return -1;
  }

  int yes = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes)) < 0) {
    printf("[linux-wake] SO_BROADCAST failed errno=%d\n", errno);
    close(fd);
    return -1;
  }

  struct sockaddr_in dst;
  memset(&dst, 0, sizeof(dst));
  dst.sin_family = AF_INET;
  dst.sin_port = htons(LINUX_WAKE_BEACON_PORT);
  dst.sin_addr.s_addr = htonl(INADDR_BROADCAST);

  char payload[160];
  int len = snprintf(payload, sizeof(payload),
                     "PS5LINUX_ARMED v1 token=%s fw=%04x",
                     LINUX_WAKE_BEACON_TOKEN, firmware_version);
  if (len <= 0 || len >= (int)sizeof(payload)) {
    printf("[linux-wake] payload formatting failed\n");
    close(fd);
    return -1;
  }

  int ok = 0;
  for (int i = 0; i < LINUX_WAKE_BEACON_REPEATS; i++) {
    ssize_t sent = sendto(fd, payload, (size_t)len, 0,
                          (const struct sockaddr *)&dst, sizeof(dst));
    if (sent == len) {
      ok = 1;
      printf("[linux-wake] beacon %d/%d sent: %s\n", i + 1,
             LINUX_WAKE_BEACON_REPEATS, payload);
    } else {
      printf("[linux-wake] beacon %d/%d failed errno=%d sent=%zd\n", i + 1,
             LINUX_WAKE_BEACON_REPEATS, errno, sent);
    }
    if (i + 1 < LINUX_WAKE_BEACON_REPEATS) {
      usleep(LINUX_WAKE_BEACON_INTERVAL_US);
    }
  }

  close(fd);
  return ok ? 0 : -1;
#else
  (void)firmware_version;
  return 0;
#endif
}
