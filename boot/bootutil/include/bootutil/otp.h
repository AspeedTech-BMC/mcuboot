#pragma once

#include <soc.h>

#define DWORD                     4
#define KEY_RETIREMENT_DW_ADDR    0x6f0

#if defined(CONFIG_OTP_SIM)
#define FLASH_OTP_DEV                    "fmc_cs0"
#define FLASH_OTP_DATA_BASE              0xfc000
#define FLASH_OTP_CONF_BASE              0xfe000
#define FLASH_OTP_KEY_RETIREMENT_ADDR    ( FLASH_OTP_DATA_BASE + (KEY_RETIREMENT_DW_ADDR * DWORD) )
#endif

void set_dev_fw_key_id(int key_id);
int get_dev_fw_key_id(void);
