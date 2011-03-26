/*
 * (C) 2007-09 - Luca Deri <deri@ntop.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>
*/

#include "n2n.h"

#ifdef __linux__

static void read_mac(char *ifname, char *mac_addr) {
  int _sock, res;
  struct ifreq ifr;
  macstr_t mac_addr_buf;

  memset (&ifr,0,sizeof(struct ifreq));

  /* Dummy socket, just to make ioctls with */
  _sock=socket(PF_INET, SOCK_DGRAM, 0);
  strcpy(ifr.ifr_name, ifname);
  res = ioctl(_sock,SIOCGIFHWADDR,&ifr);
  if (res<0) {
    perror ("Get hw addr");
  } else
    memcpy(mac_addr, ifr.ifr_ifru.ifru_hwaddr.sa_data, 6);

  traceEvent(TRACE_NORMAL, "Interface %s has MAC %s",
	     ifname,
	     macaddr_str(mac_addr, mac_addr_buf, sizeof(mac_addr_buf)));
  close(_sock);
}

/* ********************************** */

/** @brief  Open and configure the TAP device for packet read/write.
 *
 *  This routine creates the interface via the tuntap driver then uses ifconfig
 *  to configure address/mask and MTU.
 *
 *  @param device      - [inout] a device info holder object
 *  @param dev         - user-defined name for the new iface, 
 *                       if NULL system will assign a name
 *  @param device_ip   - address of iface
 *  @param device_mask - netmask for device_ip
 *  @param mtu         - MTU for device_ip
 *
 *  @return - negative value on error
 *          - non-negative file-descriptor on success
 */
int tuntap_open(tuntap_dev *device, 
                char *dev, /* user-definable interface name, eg. edge0 */
                char *device_ip, 
                char *device_mask,
                const char * device_mac,
		int mtu) {
  char *tuntap_device = "/dev/net/tun";
#define N2N_LINUX_SYSTEMCMD_SIZE 128
  char buf[N2N_LINUX_SYSTEMCMD_SIZE];
  struct ifreq ifr;
  int rc;

  device->fd = open(tuntap_device, O_RDWR);
  if(device->fd < 0) {
    printf("ERROR: ioctl() [%s][%d]\n", strerror(errno), errno);
    return -1;
  }

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TAP|IFF_NO_PI; /* Want a TAP device for layer 2 frames. */
  strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  rc = ioctl(device->fd, TUNSETIFF, (void *)&ifr);

  if(rc < 0) {
    traceEvent(TRACE_ERROR, "ioctl() [%s][%d]\n", strerror(errno), rc);
    close(device->fd);
    return -1;
  }

  if ( device_mac )
  {
      /* Set the hw address before bringing the if up. */
      snprintf(buf, sizeof(buf), "/sbin/ifconfig %s hw ether %s",
               ifr.ifr_name, device_mac );
      system(buf);
      traceEvent(TRACE_INFO, "Setting MAC: %s", buf);
  }

  snprintf(buf, sizeof(buf), "/sbin/ifconfig %s %s netmask %s mtu %d up",
           ifr.ifr_name, device_ip, device_mask, mtu);
  system(buf);
  traceEvent(TRACE_INFO, "Bringing up: %s", buf);

  device->ip_addr = inet_addr(device_ip);
  device->device_mask = inet_addr(device_mask);
  read_mac(dev, (char*)device->mac_addr);
  return(device->fd);
}

int tuntap_read(struct tuntap_dev *tuntap, unsigned char *buf, int len) {
  return(read(tuntap->fd, buf, len));
}

int tuntap_write(struct tuntap_dev *tuntap, unsigned char *buf, int len) {
  return(write(tuntap->fd, buf, len));
}

void tuntap_close(struct tuntap_dev *tuntap) {
  close(tuntap->fd);
}

#endif /* #ifdef __linux__ */
