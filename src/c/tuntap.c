// VpnCloud - Peer-to-Peer VPN
// Copyright (C) 2015-2016  Dennis Schwerdel
// This software is licensed under GPL-3 or newer (see LICENSE.md)

#include <stdint.h>
#include <net/if.h>

#include <string.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <unistd.h>

#include <string.h> // strlcpy
#include <sys/kern_control.h> // struct socketaddr_ctl
#include <fcntl.h>

#ifdef HAVE_NET_IF_UTUN_H
  #include <net/if_utun.h> // UTUN_CONTROL_NAME

  int setup_tun_device(int32_t fd, char *ifname) {
      socklen_t ifname_len = sizeof(ifname);
      struct ctl_info ctlInfo;
      int utunnum = -1;

      fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
      if (fd < 0) {
          perror("socket");
          return fd;
      }

      strlcpy(ctlInfo.ctl_name, UTUN_CONTROL_NAME, sizeof(ctlInfo.ctl_name));

      if (ifname && (strcmp("utun", ifname) != 0 )) {
          sscanf(ifname, "utun%d", &utunnum);
      }
      memset(ifname, 0, sizeof(ifname));

      struct sockaddr_ctl sc;

      if (ioctl(fd, CTLIOCGINFO, &ctlInfo) == -1) {
          perror("ioctl");
          close(fd);
          return -1;
      }

      sc.sc_id = ctlInfo.ctl_id;
      sc.sc_len = sizeof(sc);
      sc.sc_family = AF_SYSTEM;
      sc.ss_sysaddr = AF_SYS_CONTROL;
      sc.sc_unit = utunnum + 1;

      if (connect(fd, (struct sockaddr *)&sc, sizeof(sc)) < 0) {
          perror("connect");
          close(fd);
          return -1;
      }

      if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifname_len) < 0) {
          perror("getsockopt");
          close(fd);
          return -1;
      }

      if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
          perror("fcntl");
          close(fd);
          return -1;
      }

      return fd;
  }

  int setup_tap_device(int32_t fd, char *ifname) {
      return -1;
  }

  /* int main() {
      int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
      if (fd < 0) {
          perror("socket");
          return fd;
      }
      setup_tun_device(fd, "");
      printf("%d", fd);
      sleep(5);
      close(fd);
      return 0;
  }*/
#else
  #include <linux/if_tun.h>

  int32_t setup_device(int32_t fd, char *ifname, int32_t flags) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = flags;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) return 1;
    strncpy(ifname, ifr.ifr_name, IFNAMSIZ);
    return fd;
  }

  int32_t setup_tap_device(int32_t fd, char *ifname) {
    return setup_device(fd, ifname, IFF_TAP | IFF_NO_PI);
  }

  int32_t setup_tun_device(int32_t fd, char *ifname) {
    return setup_device(fd, ifname, IFF_TUN | IFF_NO_PI);
  }
#endif
