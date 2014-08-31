/* include/linux/touch_wake.h */

#ifndef _LINUX_TOUCH_WAKE_H
#define _LINUX_TOUCH_WAKE_H

#include <linux/input.h>

extern void touchscreen_enable(void);
extern void touchscreen_disable(void);

bool touchwake_is_enabled(void);
void powerkey_pressed(void);
void powerkey_released(void);
void touch_press(void);
bool device_is_suspended(void);
void set_powerkeydev(struct input_dev *input_device);

#endif