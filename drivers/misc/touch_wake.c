/* drivers/misc/touch_wake.c
 *
 * Copyright 2011  Ezekeel
 * Copyright 2013  Stratos Karafotis stratosk@semaphore.gr
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/init.h>
#include <linux/device.h>
#include <linux/miscdevice.h>
#include <linux/touch_wake.h>
#include <linux/workqueue.h>
#include <linux/earlysuspend.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/wakelock.h>
#include <linux/input.h>
#include <linux/module.h>
#include <linux/jiffies.h>
#include <linux/leds.h>

#define TIME_LONGPRESS		(500)
#define POWERPRESS_DELAY	(40)
#define POWERPRESS_TIMEOUT	(1000)
#define DEF_TOUCHOFF_DELAY	(45000);

static struct input_dev *powerkey_device;
static struct wake_lock touchwake_wake_lock;
static struct timeval last_powerkeypress;

static bool touchwake_enabled;
static bool touch_disabled;
static bool device_suspended;
static bool timed_out;
static unsigned int touchoff_delay;
static unsigned int powerkey_flag;

static void touchwake_touchoff(struct work_struct *touchoff_work);
static DECLARE_DELAYED_WORK(touchoff_work, touchwake_touchoff);
static void press_powerkey(struct work_struct *ws);
static DECLARE_DELAYED_WORK(presspower_work, press_powerkey);
static DEFINE_MUTEX(lock);

static struct led_trigger touchwake_led_trigger = {
	.name           = "touchwake",
};

static void touchwake_disable_touch(void)
{
	pr_info("%s: disable touch controls\n", __func__);
	touchscreen_disable();
	touch_disabled = true;
    
	return;
}

static void touchwake_enable_touch(void)
{
	pr_info("%s: enable touch controls\n", __func__);
	touchscreen_enable();
	touch_disabled = false;
    
	return;
}

bool touchwake_is_enabled(void)
{
	return touchwake_enabled;
}
EXPORT_SYMBOL(touchwake_is_enabled);

static void touchwake_early_suspend(struct early_suspend *h)
{
	if (!touchwake_enabled)
		goto out;
    
	if (timed_out) {
		wake_lock(&touchwake_wake_lock);
		led_trigger_event(&touchwake_led_trigger, LED_FULL);
		schedule_delayed_work(&touchoff_work,
                              msecs_to_jiffies(touchoff_delay));
	} else
		touchwake_disable_touch();
    
out:
	device_suspended = true;
}

static void touchwake_late_resume(struct early_suspend *h)
{
	if (!touchwake_enabled)
		goto out;
    
	cancel_delayed_work(&touchoff_work);
	flush_scheduled_work();
    
	wake_unlock(&touchwake_wake_lock);
    
	if (touch_disabled)
		touchwake_enable_touch();
    
	led_trigger_event(&touchwake_led_trigger, LED_OFF);
	timed_out = true;
    
out:
	device_suspended = false;
}

static struct early_suspend touchwake_suspend_data = {
	.level = EARLY_SUSPEND_LEVEL_BLANK_SCREEN,
	.suspend = touchwake_early_suspend,
	.resume = touchwake_late_resume,
};

static void touchwake_touchoff(struct work_struct *touchoff_work)
{
	touchwake_disable_touch();
	wake_unlock(&touchwake_wake_lock);
	led_trigger_event(&touchwake_led_trigger, LED_OFF);
    
	return;
}

static void press_powerkey(struct work_struct *ws)
{
	unsigned long delay;
    
	if (powerkey_flag == 0) {
		pr_debug("%s: power key down\n", __func__);
        
		input_report_key(powerkey_device, KEY_POWER, 1);
		input_sync(powerkey_device);
        
		powerkey_flag = 1;
        
		delay = msecs_to_jiffies(POWERPRESS_DELAY);
		schedule_delayed_work(&presspower_work, delay);
	} else if (powerkey_flag == 1) {
		pr_debug("%s: power key up\n", __func__);
        
		input_report_key(powerkey_device, KEY_POWER, 0);
		input_sync(powerkey_device);
        
		powerkey_flag = 2;
        
		delay = msecs_to_jiffies(POWERPRESS_DELAY);
		schedule_delayed_work(&presspower_work, delay);
	} else if (powerkey_flag == 2) {
		pr_debug("%s: delay\n", __func__);
        
		powerkey_flag = 3;
        
		delay = msecs_to_jiffies(POWERPRESS_TIMEOUT);
		schedule_delayed_work(&presspower_work, delay);
	} else if (powerkey_flag == 3) {
		pr_debug("%s: release mutex\n", __func__);
        
		powerkey_flag = 0;
        
		mutex_unlock(&lock);
	}
}

static ssize_t touchwake_status_read(struct device *dev,
                                     struct device_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u\n", (touchwake_enabled ? 1 : 0));
}

static ssize_t touchwake_status_write(struct device *dev,
                                      struct device_attribute *attr, const char *buf, size_t size)
{
	unsigned int data;
	int ret;
    
	ret = sscanf(buf, "%u\n", &data);
    
	if (ret != 1 || data < 0) {
		pr_info("%s: invalid input\n", __func__);
		return -EINVAL;
	}
    
	pr_debug("%s: %u\n", __func__, data);
    
	if (data == 1) {
		pr_info("%s: TOUCHWAKE function enabled\n", __func__);
		touchwake_enabled = true;
	} else if (data == 0) {
		pr_info("%s: TOUCHWAKE function disabled\n", __func__);
		touchwake_enabled = false;
	}
    
	return size;
}

static ssize_t touchwake_delay_read(struct device *dev,
                                    struct device_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%u\n", touchoff_delay);
}

static ssize_t touchwake_delay_write(struct device *dev,
                                     struct device_attribute *attr, const char *buf, size_t size)
{
	unsigned int data;
	int ret;
    
	ret = sscanf(buf, "%u\n", &data);
    
	if (ret != 1 || data < 1) {
		pr_info("%s: invalid input\n", __func__);
		return -EINVAL;
	}
    
	touchoff_delay = data;
	pr_info("TOUCHWAKE delay set to %u\n", touchoff_delay);
    
	return size;
}

static DEVICE_ATTR(enabled, S_IRUGO | S_IWUGO, touchwake_status_read,
                   touchwake_status_write);
static DEVICE_ATTR(delay, S_IRUGO | S_IWUGO, touchwake_delay_read,
                   touchwake_delay_write);

static struct attribute *touchwake_notification_attributes[] = {
	&dev_attr_enabled.attr,
	&dev_attr_delay.attr,
	NULL
};

static struct attribute_group touchwake_notification_group = {
	.attrs  = touchwake_notification_attributes,
};

static struct miscdevice touchwake_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "touchwake",
};

void powerkey_pressed(void)
{
	do_gettimeofday(&last_powerkeypress);
    
	return;
}
EXPORT_SYMBOL(powerkey_pressed);

void powerkey_released(void)
{
	struct timeval now;
	int time_pressed;
    
	do_gettimeofday(&now);
    
	time_pressed = (now.tv_sec - last_powerkeypress.tv_sec) * MSEC_PER_SEC +
    (now.tv_usec - last_powerkeypress.tv_usec) / USEC_PER_MSEC;
    
	if (time_pressed > POWERPRESS_DELAY && time_pressed < TIME_LONGPRESS) {
		timed_out = false;
		pr_debug("%s: timed_out false: %d", __func__, time_pressed);
	}
    
	return;
}
EXPORT_SYMBOL(powerkey_released);

void touch_press(void)
{
	unsigned long delay = 10;
    
	pr_debug("%s: touch pressed\n", __func__);
	if (touchwake_enabled && device_suspended && mutex_trylock(&lock))
		schedule_delayed_work(&presspower_work, delay);
    
	return;
}
EXPORT_SYMBOL(touch_press);

void set_powerkeydev(struct input_dev *input_device)
{
	powerkey_device = input_device;
    
	return;
}
EXPORT_SYMBOL(set_powerkeydev);

bool device_is_suspended(void)
{
	return device_suspended && !mutex_is_locked(&lock);
}
EXPORT_SYMBOL(device_is_suspended);

static int __init touchwake_control_init(void)
{
	int ret;
    
	touchwake_enabled = false;
	touch_disabled = false;
	device_suspended = false;
	timed_out = true;
	touchoff_delay = DEF_TOUCHOFF_DELAY;
	powerkey_flag = 0;
    
	pr_info("%s misc_register(%s)\n", __func__, touchwake_device.name);
	ret = misc_register(&touchwake_device);
    
	if (ret) {
		pr_err("%s misc_register(%s) fail\n", __func__,
               touchwake_device.name);
		return 1;
	}
    
	register_early_suspend(&touchwake_suspend_data);
    
	wake_lock_init(&touchwake_wake_lock, WAKE_LOCK_SUSPEND,
                   "touchwake_wake");
    
	if (sysfs_create_group(&touchwake_device.this_device->kobj,
                           &touchwake_notification_group) < 0) {
		pr_err("%s sysfs_create_group fail\n", __func__);
		pr_err("Failed to create sysfs group for device (%s)!\n",
               touchwake_device.name);
	}
    
	do_gettimeofday(&last_powerkeypress);
    
	powerkey_flag = 0;
    
	ret = led_trigger_register(&touchwake_led_trigger);
    
	return 0;
}

static void __exit touchwake_control_exit(void)
{
	led_trigger_unregister(&touchwake_led_trigger);
}

device_initcall(touchwake_control_init);