#pragma once
#include "bootutil/bootutil.h"
#include <stddef.h>

#define PAGE_SIZE                         (4 * 1024)

int dice_start(size_t cert_type, struct boot_rsp *boot_rsp);
