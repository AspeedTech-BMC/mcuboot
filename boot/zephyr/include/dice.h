#pragma once
#include "bootutil/bootutil.h"
#include <stddef.h>

int dice_start(size_t cert_type, struct boot_rsp *boot_rsp);
