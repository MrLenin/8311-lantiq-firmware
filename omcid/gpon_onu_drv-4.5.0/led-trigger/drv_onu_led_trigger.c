/*
 * LED Kernel ONU Trigger
 *
 * Toggles the LED to reflect the link and traffic state of a named ONU device
 *
 * Copyright 2007 Oliver Jowett <oliver@opencloud.com>
 *
 * Derived from ledtrig-timer.c which is:
 *  Copyright 2005-2006 Openedhand Ltd.
 *  Author: Richard Purdie <rpurdie@openedhand.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#if defined(LINUX) && !defined(ONU_SIMULATION)

#include <linux/module.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/device.h>
#include <linux/sysdev.h>
#include <linux/timer.h>
#include <linux/ctype.h>
#include <linux/leds.h>
#include <linux/version.h>
#include <net/net_namespace.h>

#include "drv_onu_notifier.h"
#include "drv_onu_led_trigger.h"

/*
 * Configurable sysfs attributes:
 *
 * device_name - network device name to monitor
 *
 * interval - duration of LED blink, in milliseconds
 *
 * mode - either "none" (LED is off) or a space separated list of one or more of:
 *   link: LED's normal state reflects whether the link is up (has carrier) or not
 *   tx:   LED blinks on transmitted data
 *   rx:   LED blinks on receive data
 *
 * Some suggestions:
 *
 *  Simple link status LED for first ethernet port:
 *  $ echo onu >someled/trigger
 *  $ echo mac0 >someled/device_name
 *  $ echo link >someled/mode
 *
 *  Ethernet-style link/activity LED for first ethernet port:
 *  $ echo onu >someled/trigger
 *  $ echo mac0 >someled/device_name
 *  $ echo "link tx rx" >someled/mode
 *
 *  Modem-style tx/rx LEDs for GPON uplink:
 *  $ echo onu >led1/trigger
 *  $ echo gpon >led1/device_name
 *  $ echo tx >led1/mode
 *  $ echo onu >led2/trigger
 *  $ echo gpon >led2/device_name
 *  $ echo rx >led2/mode
 *
 */

static inline void led_set_brightness(struct led_classdev *led_cdev,
                                        enum led_brightness value)
{
	if (value > led_cdev->max_brightness)
		value = led_cdev->max_brightness;
	led_cdev->brightness = value;
	if (!(led_cdev->flags & LED_SUSPENDED))
		led_cdev->brightness_set(led_cdev, value);
}

#define MODE_LINK 1
#define MODE_TX   2
#define MODE_RX   4

struct led_onu_data {
	rwlock_t lock;
	struct timer_list timer;
	struct led_classdev *led_cdev;
	struct onu_notifier_device *onu_dev;
	char device_name[IFNAMSIZ];
	unsigned interval;
	unsigned mode;
	unsigned link_up;
	unsigned last_activity;
};

static void set_baseline_state(struct led_onu_data *trigger_data)
{
	if ((trigger_data->mode & MODE_LINK) != 0 && trigger_data->link_up)
		led_set_brightness(trigger_data->led_cdev, LED_FULL);
	else
		led_set_brightness(trigger_data->led_cdev, LED_OFF);

	mod_timer(&trigger_data->timer, jiffies + trigger_data->interval);
}

static ssize_t led_device_name_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	struct led_classdev *led_cdev = dev_get_drvdata(dev);
	struct led_onu_data *trigger_data = led_cdev->trigger_data;

	read_lock(&trigger_data->lock);
	sprintf(buf, "%s\n", trigger_data->device_name);
	read_unlock(&trigger_data->lock);

	return strlen(buf) + 1;
}

static ssize_t led_device_name_store(struct device *dev,
				     struct device_attribute *attr, const char *buf, size_t size)
{
	struct led_classdev *led_cdev = dev_get_drvdata(dev);
	struct led_onu_data *trigger_data = led_cdev->trigger_data;

	if (size < 0 || size >= IFNAMSIZ)
		return -EINVAL;

	write_lock(&trigger_data->lock);

	strcpy(trigger_data->device_name, buf);
	if (size > 0 && trigger_data->device_name[size-1] == '\n')
		trigger_data->device_name[size-1] = 0;

	if (trigger_data->device_name[0] != 0) {
		/* check for existing device to update from */
		trigger_data->onu_dev = onu_get_by_name(trigger_data->device_name);
		if (trigger_data->onu_dev != NULL)
			trigger_data->link_up = (onu_get_flags(trigger_data->onu_dev) & ONU_LOWER_UP) != 0;
		set_baseline_state(trigger_data); /* updates LEDs, may start timers */
	}

	write_unlock(&trigger_data->lock);
	return size;
}

static DEVICE_ATTR(device_name, 0644, led_device_name_show, led_device_name_store);

static ssize_t led_mode_show(struct device *dev,
			     struct device_attribute *attr, char *buf)
{
	struct led_classdev *led_cdev = dev_get_drvdata(dev);
	struct led_onu_data *trigger_data = led_cdev->trigger_data;

	read_lock(&trigger_data->lock);

	if (trigger_data->mode == 0) {
		strcpy(buf, "none\n");
	} else {
		if (trigger_data->mode & MODE_LINK)
			strcat(buf, "link ");
		if (trigger_data->mode & MODE_TX)
			strcat(buf, "tx ");
		if (trigger_data->mode & MODE_RX)
			strcat(buf, "rx ");
		strcat(buf, "\n");
	}

	read_unlock(&trigger_data->lock);

	return strlen(buf)+1;
}

static ssize_t led_mode_store(struct device *dev,
			      struct device_attribute *attr, const char *buf, size_t size)
{
	struct led_classdev *led_cdev = dev_get_drvdata(dev);
	struct led_onu_data *trigger_data = led_cdev->trigger_data;
	char copybuf[32];
	int new_mode = -1;
	char *p, *token;

	/* take a copy since we don't want to trash the inbound buffer when using strsep */
	strncpy(copybuf, buf, sizeof(copybuf));
	copybuf[31] = 0;
	p = copybuf;

	while ((token = strsep(&p, " \t\n")) != NULL) {
		if (!*token)
			continue;

		if (new_mode == -1)
			new_mode = 0;

		if (!strcmp(token, "none"))
			new_mode = 0;
		else if (!strcmp(token, "tx"))
			new_mode |= MODE_TX;
		else if (!strcmp(token, "rx"))
			new_mode |= MODE_RX;
		else if (!strcmp(token, "link"))
			new_mode |= MODE_LINK;
		else
			return -EINVAL;
	}

	if (new_mode == -1)
		return -EINVAL;

	write_lock(&trigger_data->lock);
	trigger_data->mode = new_mode;
	set_baseline_state(trigger_data);
	write_unlock(&trigger_data->lock);

	return size;
}

static DEVICE_ATTR(mode, 0644, led_mode_show, led_mode_store);

static ssize_t led_interval_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct led_classdev *led_cdev = dev_get_drvdata(dev);
	struct led_onu_data *trigger_data = led_cdev->trigger_data;

	read_lock(&trigger_data->lock);
	sprintf(buf, "%u\n", jiffies_to_msecs(trigger_data->interval));
	read_unlock(&trigger_data->lock);

	return strlen(buf) + 1;
}

static ssize_t led_interval_store(struct device *dev,
				  struct device_attribute *attr, const char *buf, size_t size)
{
	struct led_classdev *led_cdev = dev_get_drvdata(dev);
	struct led_onu_data *trigger_data = led_cdev->trigger_data;
	int ret = -EINVAL;
	char *after;
	unsigned long value = simple_strtoul(buf, &after, 10);
	size_t count = after - buf;

	if (*after && isspace(*after))
		count++;

	/* impose some basic bounds on the timer interval */
	if (count == size && value >= 5 && value <= 10000) {
		write_lock(&trigger_data->lock);
		trigger_data->interval = msecs_to_jiffies(value);
		set_baseline_state(trigger_data); // resets timer
		write_unlock(&trigger_data->lock);
		ret = count;
	}

	return ret;
}

static DEVICE_ATTR(interval, 0644, led_interval_show, led_interval_store);

/* here's the real work! */
static void onudev_trig_timer(unsigned long arg)
{
	struct led_onu_data *trigger_data = (struct led_onu_data *)arg;
	const struct onu_notifier_device_stats *dev_stats;
	unsigned new_activity;

	if (trigger_data->onu_dev == NULL)
		return;

	write_lock(&trigger_data->lock);

	trigger_data->link_up = (onu_get_flags(trigger_data->onu_dev) & ONU_LOWER_UP) != 0;

	if (!trigger_data->link_up || (trigger_data->mode & (MODE_TX | MODE_RX)) == 0) {
		/* handle link only LED */
		led_set_brightness(trigger_data->led_cdev, ((trigger_data->mode & MODE_LINK) != 0 && trigger_data->link_up) ? LED_FULL : LED_OFF);
		goto restart;
	}

	dev_stats = onu_get_stats(trigger_data->onu_dev);
	new_activity =
		((trigger_data->mode & MODE_TX) ? dev_stats->tx_packets : 0) +
		((trigger_data->mode & MODE_RX) ? dev_stats->rx_packets : 0);

	if (trigger_data->mode & MODE_LINK) {
		/* base state is ON (link present) */
		/* if there's no link, we don't get this far and the LED is off */

		/* OFF -> ON always */
		/* ON -> OFF on activity */
		if (trigger_data->led_cdev->brightness == LED_OFF) {
			led_set_brightness(trigger_data->led_cdev, LED_FULL);
		} else if (trigger_data->last_activity != new_activity) {
			led_set_brightness(trigger_data->led_cdev, LED_OFF);
		}
	} else {
		/* base state is OFF */
		/* ON -> OFF always */
		/* OFF -> ON on activity */
		if (trigger_data->led_cdev->brightness == LED_FULL) {
			led_set_brightness(trigger_data->led_cdev, LED_OFF);
		} else if (trigger_data->last_activity != new_activity) {
			led_set_brightness(trigger_data->led_cdev, LED_FULL);
		}
	}

	trigger_data->last_activity = new_activity;

restart:
	mod_timer(&trigger_data->timer, jiffies + trigger_data->interval);
	write_unlock(&trigger_data->lock);
}

static void onudev_trig_activate(struct led_classdev *led_cdev)
{
	struct led_onu_data *trigger_data;
	int rc;

	trigger_data = kzalloc(sizeof(struct led_onu_data), GFP_KERNEL);
	if (!trigger_data)
		return;

	rwlock_init(&trigger_data->lock);

	setup_timer(&trigger_data->timer, onudev_trig_timer, (unsigned long) trigger_data);

	trigger_data->led_cdev = led_cdev;
	trigger_data->onu_dev = NULL;
	trigger_data->device_name[0] = 0;

	trigger_data->mode = 0;
	trigger_data->interval = msecs_to_jiffies(50);
	trigger_data->link_up = 0;
	trigger_data->last_activity = 0;

	led_cdev->trigger_data = trigger_data;

	rc = device_create_file(led_cdev->dev, &dev_attr_device_name);
	if (rc)
		goto err_out;
	rc = device_create_file(led_cdev->dev, &dev_attr_mode);
	if (rc)
		goto err_out_device_name;
	rc = device_create_file(led_cdev->dev, &dev_attr_interval);
	if (rc)
		goto err_out_mode;

	return;

err_out_mode:
	device_remove_file(led_cdev->dev, &dev_attr_mode);
err_out_device_name:
	device_remove_file(led_cdev->dev, &dev_attr_device_name);
err_out:
	led_cdev->trigger_data = NULL;
	kfree(trigger_data);
}

static void onudev_trig_deactivate(struct led_classdev *led_cdev)
{
	struct led_onu_data *trigger_data = led_cdev->trigger_data;

	if (trigger_data) {

		device_remove_file(led_cdev->dev, &dev_attr_device_name);
		device_remove_file(led_cdev->dev, &dev_attr_mode);
		device_remove_file(led_cdev->dev, &dev_attr_interval);

		write_lock(&trigger_data->lock);

		if (trigger_data->onu_dev) {
			#if 0
			dev_put(trigger_data->onu_dev);
			#endif
			trigger_data->onu_dev = NULL;
		}

		write_unlock(&trigger_data->lock);

		del_timer_sync(&trigger_data->timer);

		kfree(trigger_data);
	}
}

static struct led_trigger onudev_led_trigger = {
	.name     = "onu",
	.activate = onudev_trig_activate,
	.deactivate = onudev_trig_deactivate,
};

static int __init onudev_trig_init(void)
{
	return led_trigger_register(&onudev_led_trigger);
}

static void __exit onudev_trig_exit(void)
{
	led_trigger_unregister(&onudev_led_trigger);
}

module_init(onudev_trig_init);
module_exit(onudev_trig_exit);

MODULE_AUTHOR("Ralph Hempel <ralph.hempel@lantiq.com>");
MODULE_DESCRIPTION(ONU_LED_TRIGGER_DESC);
MODULE_LICENSE("GPL");

#endif /* #if defined(LINUX) && !defined(ONU_SIMULATION) */
