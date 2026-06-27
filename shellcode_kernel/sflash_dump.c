/* sflash_dump.c — Dump serial flash via ICC mailbox polling
 *
 * Runs in the kernel shellcode after HV defeat.
 * Accesses ICC mailbox registers directly via DMAP (no IRQs needed).
 * Dumps NVS area via ICC NVS read commands.
 * Stores dump in cave area for Linux to access.
 */

#include "sflash_dump.h"
#include "../include/config.h"
#include "../include/linux.h"
#include "utils.h"
#include <stddef.h>

/* ICC mailbox register offsets (within icc_base = BAR4) */
#define ICC_QUERY_OFFSET    0x000
#define ICC_REPLY_OFFSET    0x800
#define ICC_REG_SOW         0x7f0
#define ICC_REG_SOR         0x7f4
#define ICC_REG_EMW         0xff0
#define ICC_REG_EMR         0xff4

/* ICC doorbell register offsets (within icc_doorbell = BAR2 + 0x108000) */
#define ICC_REG_DOORBELL    0x04
#define ICC_REG_INTR_STATUS 0x14

#define ICC_SEND            0x01
#define ICC_ACK             0x02
#define ICC_MSG_TYPE_REPLY  0x4000
#define ICC_MSG_TYPE_NOTIF  0x8000

/* ICC message format */
#define ICC_MSG_MIN_SIZE    0x20
#define ICC_MSG_MAX_SIZE    0x7f0
#define ICC_MSG_HEADER_SIZE 12  /* sizeof(icc_msg header) */

#define ICC_SERVICE_ID_NVS  0x03

/* Serial flash layout */
#define SFLASH_NVS_OFFSET   0x1C4000
#define SFLASH_NVS_SIZE     0x3C000   /* 240KB */
#define SFLASH_TOTAL_SIZE   0x200000  /* 2MB */

/* PCIe BAR physical addresses for spcie */
#define SPCIE_BAR2_PA       0x85200000ULL  /* 2MB */
#define SPCIE_BAR4_PA       0x85400000ULL  /* 512K (pervasive0) */

#define ICC_BASE_PA         SPCIE_BAR4_PA
#define ICC_DOORBELL_PA     (SPCIE_BAR2_PA + 0x108000ULL)

#define ICC_MAX_DATA_LEN    (ICC_MSG_MAX_SIZE - ICC_MSG_HEADER_SIZE)

/* ICC message header */
struct icc_msg {
  uint8_t  magic;
  uint8_t  service_id;
  uint16_t msg_type;
  uint16_t unk_04;
  uint16_t id;
  uint16_t length;
  uint16_t checksum;
  uint8_t  data[];
} __attribute__((packed));

static uint16_t icc_checksum(struct icc_msg *msg) {
  uint16_t sum = 0;
  for (uint16_t i = 0; i < msg->length; i++)
    sum += ((uint8_t *)msg)[i];
  return sum;
}

static volatile uint8_t *icc_base;
static volatile uint32_t *icc_doorbell;
static uint16_t icc_xtn_id = 1;

static void icc_write_reg(uint32_t offset, uint32_t val) {
  *(volatile uint32_t *)(icc_base + offset) = val;
}

static void icc_write_reg16(uint32_t offset, uint16_t val) {
  *(volatile uint16_t *)(icc_base + offset) = val;
}

static uint32_t icc_doorbell_read(uint32_t offset) {
  return *(volatile uint32_t *)((uint8_t *)icc_doorbell + offset);
}

static void icc_doorbell_write(uint32_t offset, uint32_t val) {
  *(volatile uint32_t *)((uint8_t *)icc_doorbell + offset) = val;
}

static int icc_send_query(uint8_t *query) {
  struct icc_msg *msg = (struct icc_msg *)query;

  if (msg->length < ICC_MSG_MIN_SIZE)
    msg->length = ICC_MSG_MIN_SIZE;
  msg->magic = 0x42;
  msg->unk_04 = 3;
  msg->id = icc_xtn_id++;
  msg->checksum = icc_checksum(msg);

  /* Clear reply ready */
  icc_write_reg16(ICC_REG_SOR, 0);

  /* Write query bytes */
  for (uint16_t i = 0; i < msg->length; i++)
    icc_base[ICC_QUERY_OFFSET + i] = query[i];

  /* Signal query ready */
  icc_write_reg16(ICC_REG_SOW, 1);

  /* Ring doorbell */
  icc_doorbell_write(ICC_REG_DOORBELL, ICC_SEND);

  /* Small delay for EMC to process */
  for (volatile int j = 0; j < 100000; j++)
    ;

  return 0;
}

static int icc_poll_reply(uint8_t *reply, int timeout_ms) {
  /* Rough delay: ~1ms at ~1.6GHz */
  for (int i = 0; i < timeout_ms; i++) {
    for (volatile int j = 0; j < 800000; j++)
      ;

    uint32_t status = icc_doorbell_read(ICC_REG_INTR_STATUS);
    if (!status)
      continue;

    /* Ack interrupt */
    icc_doorbell_write(ICC_REG_INTR_STATUS, status);

    if (status & ICC_SEND) {
      struct icc_msg *msg = (struct icc_msg *)(icc_base + ICC_REPLY_OFFSET);
      uint16_t len = msg->length;
      if (len > ICC_MSG_MAX_SIZE)
        len = ICC_MSG_MAX_SIZE;

      /* Copy reply */
      for (uint16_t j = 0; j < len; j++)
        reply[j] = icc_base[ICC_REPLY_OFFSET + j];

      /* Ack the message */
      icc_write_reg16(ICC_REG_EMW, 0);
      icc_write_reg16(ICC_REG_EMR, 1);
      icc_doorbell_write(ICC_REG_DOORBELL, ICC_ACK);

      if (msg->msg_type & ICC_MSG_TYPE_REPLY)
        return len;
      if (msg->msg_type & ICC_MSG_TYPE_NOTIF)
        continue; /* Skip notifications, keep polling */
    }
  }
  return -1;
}

static int icc_nvs_read(uint8_t partition, uint16_t offset, uint16_t length,
                        uint8_t *data) {
  uint8_t query[ICC_MSG_MAX_SIZE] = {0};
  uint8_t reply[ICC_MSG_MAX_SIZE] = {0};
  struct icc_msg *msg = (struct icc_msg *)query;
  int ret;

  msg->service_id = ICC_SERVICE_ID_NVS;
  msg->msg_type = 1;
  msg->length = ICC_MSG_MIN_SIZE;
  msg->data[0] = 0;           /* read */
  msg->data[1] = partition;
  *(uint16_t *)&msg->data[2] = offset;
  *(uint16_t *)&msg->data[4] = length;

  icc_send_query(query);

  ret = icc_poll_reply(reply, 2000);
  if (ret < 0)
    return -1;
  if (ret < ICC_MSG_HEADER_SIZE + 2)
    return -1;

  /* Reply data starts at data[2] */
  struct icc_msg *rsp = (struct icc_msg *)reply;
  uint16_t copy_len = length;
  if (copy_len > ret - ICC_MSG_HEADER_SIZE - 2)
    copy_len = ret - ICC_MSG_HEADER_SIZE - 2;

  /* Copy data from reply data[2..] */
  for (uint16_t i = 0; i < copy_len; i++)
    data[i] = rsp->data[2 + i];

  return copy_len;
}

static size_t sflash_copy_nvs(uint8_t *sflash_va, size_t total_copied,
                              uint8_t *buf, int len) {
  size_t nvs_remaining = SFLASH_NVS_SIZE - total_copied;

  if (len <= 0 || nvs_remaining == 0)
    return total_copied;

  if ((size_t)len > nvs_remaining)
    len = nvs_remaining;

  for (int i = 0; i < len; i++)
    sflash_va[SFLASH_NVS_OFFSET + total_copied + i] = buf[i];

  return total_copied + len;
}

void dump_sflash(struct linux_info *info) {
  uint64_t sflash_pa;
  uint8_t *sflash_va;
  size_t total_copied = 0;

  printf("[sflash] Initializing ICC mailbox polling...\n");

  /* Map ICC mailbox via DMAP */
  icc_base = (volatile uint8_t *)PHYS_TO_DMAP(ICC_BASE_PA);
  icc_doorbell = (volatile uint32_t *)PHYS_TO_DMAP(ICC_DOORBELL_PA);

  /* Use the kernel VA set by the loader (pages installed via
   * install_page_syscore). The kernel shellcode runs in syscore context
   * and can access this VA directly. */
  sflash_pa = info->sflash_dump;
  if (!sflash_pa) {
    printf("[sflash] No sflash dump address from loader, skipping\n");
    return;
  }
  /* Use the VA directly — pages were installed by the loader */
  sflash_va = (uint8_t *)sflash_pa;

  printf("[sflash] Dump PA: 0x%lx\n", sflash_pa);
  printf("[sflash] ICC base: 0x%lx, doorbell: 0x%lx\n",
         (uint64_t)icc_base, (uint64_t)icc_doorbell);

  for (size_t i = 0; i < SFLASH_TOTAL_SIZE; i++)
    sflash_va[i] = 0xff;

  /* Try reading NVS partitions (0-7) to dump the NVS area */
  for (uint8_t partition = 0; partition < 8; partition++) {
    uint32_t offset = 0;
    uint16_t chunk_len = ICC_MAX_DATA_LEN - 2;  /* reply data starts at [2] */

    if (total_copied >= SFLASH_NVS_SIZE) {
      printf("[sflash] NVS dump area full\n");
      break;
    }

    /* Try first read to see if partition exists */
    uint8_t buf[ICC_MAX_DATA_LEN];
    int n = icc_nvs_read(partition, 0, chunk_len, buf);

    if (n <= 0) {
      printf("[sflash] partition %d: no data (err=%d)\n", partition, n);
      continue;
    }

    printf("[sflash] partition %d: got %d bytes at offset 0\n", partition, n);

    /* Copy to cave area */
    total_copied = sflash_copy_nvs(sflash_va, total_copied, buf, n);

    /* Read remaining data in chunks */
    offset = n;
    while (offset < 0x10000 && total_copied < SFLASH_NVS_SIZE) {
      uint16_t read_len = chunk_len;
      uint32_t remaining = 0x10000 - offset;

      if (remaining < read_len)
        read_len = remaining;

      n = icc_nvs_read(partition, offset, read_len, buf);
      if (n <= 0)
        break;

      total_copied = sflash_copy_nvs(sflash_va, total_copied, buf, n);
      offset += n;
    }

    printf("[sflash] partition %d: total %d bytes (offset 0x%x)\n",
           partition, offset, SFLASH_NVS_OFFSET + total_copied - offset);
  }

  /* Also try to read EMC firmware area via different service IDs */
  /* Try service 0x02 (GENERAL) with msg_type 0 */
  {
    uint8_t query[ICC_MSG_MAX_SIZE] = {0};
    uint8_t reply[ICC_MSG_MAX_SIZE] = {0};
    struct icc_msg *msg = (struct icc_msg *)query;

    msg->service_id = 0x02;  /* GENERAL */
    msg->msg_type = 0x0000;
    msg->length = ICC_MSG_MIN_SIZE;

    icc_send_query(query);
    int ret = icc_poll_reply(reply, 3000);
    if (ret > 0) {
      struct icc_msg *rsp = (struct icc_msg *)reply;
      printf("[sflash] GENERAL service reply: type=0x%04x len=%d\n",
             rsp->msg_type, rsp->length);
    } else {
      printf("[sflash] GENERAL service: no reply\n");
    }
  }

  /* sflash_dump and sflash_size were already set by the loader */
  if (total_copied > 0) {
    printf("[sflash] Dumped %d bytes of NVS to PA 0x%lx\n",
           total_copied, sflash_pa);
    printf("[sflash] Total sflash region: 0x%lx bytes\n",
           info->sflash_size);
  } else {
    printf("[sflash] No NVS data dumped (ICC polling failed?)\n");
    printf("[sflash] Dump area still reserved at PA 0x%lx\n", sflash_pa);
  }
}
