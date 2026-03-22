// 仅用于 GPIO 4 控制 NAT/STA 开关的简单实现
#include "driver/gpio.h"

#define GPIO_CTRL_PIN 4
#define GPIO_CTRL_PIN_SEL  (1ULL<<GPIO_CTRL_PIN)

void gpio_ctrl_init(void)
{
    gpio_config_t io_conf = {
        .pin_bit_mask = GPIO_CTRL_PIN_SEL,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE
    };
    gpio_config(&io_conf);
}

int gpio_ctrl_sta_nat_enabled(void)
{
    // 低电平有效
    // return gpio_get_level(GPIO_CTRL_PIN) == 0;
    // 调试时先默认关闭
    return 0;
}
