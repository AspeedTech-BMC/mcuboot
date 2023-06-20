#pragma once

#include <soc.h>
#include <sys/util.h>
#include <drivers/misc/aspeed/otp_aspeed.h>

#define DWORD                     4
#define KEY_RETIREMENT_DW_ADDR    0x6f0

#define OTP_CONF3                 3
#define OTP_CONF3_CDI_EN          BIT(31)

#if defined(CONFIG_OTP_SIM)
#define FLASH_OTP_DEV                    "fmc_cs0"
#define FLASH_OTP_DATA_BASE              0xfc000
#define FLASH_OTP_CONF_BASE              0xfe000

#define FLASH_OTP_KEY_RETIREMENT_ADDR    ( FLASH_OTP_DATA_BASE + (KEY_RETIREMENT_DW_ADDR * DWORD) )

#define FLASH_OTP_CONF_DICE              ( FLASH_OTP_CONF_BASE + (OTP_CONF3 * 2 * DWORD) )
#endif

void set_dev_fw_key_id(int key_id);
int get_dev_fw_key_id(void);
