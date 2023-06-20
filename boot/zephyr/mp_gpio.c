#include "mp_gpio.h"
#include <drivers/gpio.h>

void init_mp_status_gpios(void)
{
    const struct gpio_dt_spec mp_status1 = GPIO_DT_SPEC_GET_BY_IDX(
            DT_INST(0, aspeed_pfr_gpio_mp), mp_status1_out_gpios, 0);
    const struct gpio_dt_spec mp_status2 = GPIO_DT_SPEC_GET_BY_IDX(
            DT_INST(0, aspeed_pfr_gpio_mp), mp_status2_out_gpios, 0);

    if (gpio_pin_configure_dt(&mp_status1, GPIO_OUTPUT)) {
        return;
    }

    if (gpio_pin_configure_dt(&mp_status2, GPIO_OUTPUT)) {
        return;
    }

    gpio_pin_set(mp_status1.port, mp_status1.pin, 0);
    gpio_pin_set(mp_status2.port, mp_status2.pin, 0);
}

void set_mp_status(uint8_t status1, uint8_t status2)
{
    const struct gpio_dt_spec mp_status1 = GPIO_DT_SPEC_GET_BY_IDX(
            DT_INST(0, aspeed_pfr_gpio_mp), mp_status1_out_gpios, 0);
    const struct gpio_dt_spec mp_status2 = GPIO_DT_SPEC_GET_BY_IDX(
            DT_INST(0, aspeed_pfr_gpio_mp), mp_status2_out_gpios, 0);
    gpio_pin_set(mp_status1.port, mp_status1.pin, status1);
    gpio_pin_set(mp_status2.port, mp_status2.pin, status2);
}
