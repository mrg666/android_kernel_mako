/*
 * arch/arm/mach-msm/msm_autosmp.c
 *
 * switch cores of MSM multicore cpus off/on based on demand and suspend
 * 
 * based on the msm_mpdecision code by
 * Copyright (c) 2012-2013, Dennis Rassmann <showp1984@gmail.com>
 *
 * major revision: msm_mpdecsion.c
 * July 2013, https://github.com/mrg666/android_kernel_shooter
 * revision: msm_autosmp.c
 * September 2013, https://github.com/mrg666/android_kernel_mako
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version. For more details, see the GNU 
 * General Public License included with the Linux kernel or available 
 * at www.gnu.org/licenses
 */

#include <linux/moduleparam.h>
#include <linux/earlysuspend.h>
#include <linux/init.h>
#include <linux/cpufreq.h>
#include <linux/workqueue.h>
#include <linux/completion.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <asm-generic/cputime.h>
#include <linux/hrtimer.h>
#include <linux/delay.h>
#include "acpuclock.h"
#include <linux/rq_stats.h>

#define DEBUG 0
#define STATS 0

#define DEFAULT_RQ_POLL_JIFFIES		1
#define DEFAULT_DEF_TIMER_JIFFIES	5

#define ASMP_TAG			"[ASMP]: "
#define MSM_ASMP_STARTDELAY		20000
#define MSM_ASMP_DELAY			100
#define MSM_ASMP_PAUSE			10000

#define define_one_global_ro(_name)		\
static struct global_attr _name =		\
__ATTR(_name, 0444, show_##_name, NULL)

#define define_one_global_rw(_name)		\
static struct global_attr _name =		\
__ATTR(_name, 0644, show_##_name, store_##_name)

struct msm_asmp_cpudata_t {
	struct mutex hotplug_mutex;
	int online;
#if STATS
	long long unsigned int times_hotplugged;
#endif
};
static DEFINE_PER_CPU(struct msm_asmp_cpudata_t, msm_asmp_cpudata);

static struct delayed_work msm_asmp_work;
static struct workqueue_struct *msm_asmp_workq;
static DEFINE_MUTEX(asmp_msm_cpu_lock);

static struct msm_asmp_tuners {
	unsigned int delay;
	unsigned int pause;
	bool scroff_single_core;
	unsigned int max_cpus;
	unsigned int min_cpus;
	unsigned int load_limit_up;
	unsigned int load_limit_down;
	unsigned int time_limit_up;
	unsigned int time_limit_down;
} msm_asmp_tuners_ins = {
	.delay = MSM_ASMP_DELAY,
	.pause = MSM_ASMP_PAUSE,
	.scroff_single_core = true,
	.max_cpus = CONFIG_NR_CPUS,
	.min_cpus = 1,
	.load_limit_up = 35,
	.load_limit_down = 5,
	.time_limit_up = 90,
	.time_limit_down = 450,
};

bool was_paused = false;
static cputime64_t asmp_paused_until = 0;
static cputime64_t delta_time = 0;
static cputime64_t last_time;
static int enabled = 1;

unsigned int get_rq_avg(void) {
	unsigned long flags = 0;
	unsigned int rq = 0;

	spin_lock_irqsave(&rq_lock, flags);
	rq = rq_info.rq_avg;
	rq_info.rq_avg = 0;
	spin_unlock_irqrestore(&rq_lock, flags);
	return rq;
}

static void asmp_pause(int cpu) {
	pr_info(ASMP_TAG"CPU[%d] bypassed autosmp! | pausing [%d]ms\n",
		cpu, msm_asmp_tuners_ins.pause);
	asmp_paused_until = ktime_to_ms(ktime_get()) + msm_asmp_tuners_ins.pause;
	was_paused = true;
}

#if CONFIG_NR_CPUS > 2
static int get_slowest_cpu(void) {
	int cpu, slow_cpu = 1;
	unsigned long rate, slow_rate = ULONG_MAX;

	get_online_cpus(); 
	for_each_online_cpu(cpu)
		if (cpu > 0) {
			rate = acpuclk_get_rate(cpu);
			if (rate < slow_rate) {
				slow_cpu = cpu;
				slow_rate = rate;
			}
		}
	put_online_cpus(); 
	return slow_cpu;
}
#endif

static bool asmp_cpu_down(int cpu) {
	bool ret;
	
	ret = cpu_online(cpu);
	if (ret) {
		mutex_lock(&per_cpu(msm_asmp_cpudata, cpu).hotplug_mutex);
		cpu_down(cpu);
		per_cpu(msm_asmp_cpudata, cpu).online = false;
#if STATS
		per_cpu(msm_asmp_cpudata, cpu).times_hotplugged += 1;
#endif
#if DEBUG
		pr_info(ASMP_TAG"CPU[%d] off\n");
#endif
		mutex_unlock(&per_cpu(msm_asmp_cpudata, cpu).hotplug_mutex);
	}
	return ret;
}

static bool __cpuinit asmp_cpu_up(int cpu) {
	bool ret;
	
	ret = !cpu_online(cpu);
	if (ret) {
		mutex_lock(&per_cpu(msm_asmp_cpudata, cpu).hotplug_mutex);
		cpu_up(cpu);
		per_cpu(msm_asmp_cpudata, cpu).online = true;
#if DEBUG
		pr_info(ASMP_TAG"CPU[%d] on\n");
#endif
		mutex_unlock(&per_cpu(msm_asmp_cpudata, cpu).hotplug_mutex);
	}
	return ret;
}

static void rq_work_fn(struct work_struct *work) {
	int64_t diff, now;

	now = ktime_to_ns(ktime_get());
	diff = now - rq_info.def_start_time;
	do_div(diff, 1000*1000);
	rq_info.def_interval = (unsigned int) diff;
	rq_info.def_timer_jiffies = msecs_to_jiffies(rq_info.def_interval);
	rq_info.def_start_time = now;
}

static void __cpuinit msm_asmp_work_thread(struct work_struct *work) {
	unsigned int cpu;
	int nr_cpu_online;
	unsigned int rq_avg;
	cputime64_t current_time;

	current_time = ktime_to_ms(ktime_get());
	delta_time += current_time - last_time;
	last_time = current_time;

	if (was_paused) {
		if (current_time < asmp_paused_until) {
			goto out;
		} else {
			for_each_possible_cpu(cpu) {
				if (cpu_online(cpu))
					per_cpu(msm_asmp_cpudata, cpu).online = true;
				else
					per_cpu(msm_asmp_cpudata, cpu).online = false;
			}
			was_paused = false;
			asmp_paused_until = 0;
		}
	}

	cpu = 1;
	rq_avg = get_rq_avg();
	nr_cpu_online = num_online_cpus();

	if ((nr_cpu_online < msm_asmp_tuners_ins.max_cpus) && 
	    (rq_avg >= msm_asmp_tuners_ins.load_limit_up)) {
		if (delta_time >= msm_asmp_tuners_ins.time_limit_up) {
#if CONFIG_NR_CPUS > 2
			cpu = cpumask_next_zero(0, cpu_online_mask);
#endif
			if (per_cpu(msm_asmp_cpudata, cpu).online == false) {
				if (asmp_cpu_up(cpu))
					delta_time = 0;
				else
					asmp_pause(cpu);
			}
		}
	} else if ((nr_cpu_online > msm_asmp_tuners_ins.min_cpus) &&
		   (rq_avg <= msm_asmp_tuners_ins.load_limit_down)) {
		if (delta_time >= msm_asmp_tuners_ins.time_limit_down) {
#if CONFIG_NR_CPUS > 2
			cpu = get_slowest_cpu();
#endif
			if (per_cpu(msm_asmp_cpudata, cpu).online == true) {
				if (asmp_cpu_down(cpu))
					delta_time = 0;
				else
					asmp_pause(cpu);
			}
		}
	}
out:
	if (enabled)
		queue_delayed_work(msm_asmp_workq, &msm_asmp_work,
				   msecs_to_jiffies(msm_asmp_tuners_ins.delay));
}

static void msm_asmp_early_suspend(struct early_suspend *h) {
	int cpu = 1;

	/* unplug cpu cores */
	if (msm_asmp_tuners_ins.scroff_single_core)
#if CONFIG_NR_CPUS > 2
		for (cpu = 1; cpu < nr_cpu_ids; cpu++)
#endif
			asmp_cpu_down(cpu);

	/* suspend main work thread */
	if (enabled)
		cancel_delayed_work_sync(&msm_asmp_work);

	pr_info(ASMP_TAG"msm_autosmp suspended.\n");
}

static void __cpuinit msm_asmp_late_resume(struct early_suspend *h) {
	int cpu = 1;

	/* hotplug cpu cores */
	if (msm_asmp_tuners_ins.scroff_single_core)
#if CONFIG_NR_CPUS > 2
		for (cpu = 1; cpu < nr_cpu_ids; cpu++)
#endif
			asmp_cpu_up(cpu);

	/* resume main work thread */
	if (enabled) {
		was_paused = true;
		queue_delayed_work(msm_asmp_workq, &msm_asmp_work, 
				msecs_to_jiffies(msm_asmp_tuners_ins.delay));
	}

	pr_info(ASMP_TAG"msm_autosmp resumed.\n");
}

static struct early_suspend __refdata msm_asmp_early_suspend_handler = {
	.level = EARLY_SUSPEND_LEVEL_BLANK_SCREEN,
	.suspend = msm_asmp_early_suspend,
	.resume = msm_asmp_late_resume,
};

static int __cpuinit set_enabled(const char *val, const struct kernel_param *kp) {
	int ret = 0;
	int cpu = 1;

	ret = param_set_bool(val, kp);
	if (enabled) {
		was_paused = true;
		queue_delayed_work(msm_asmp_workq, &msm_asmp_work,
				msecs_to_jiffies(msm_asmp_tuners_ins.delay));
		pr_info(ASMP_TAG"msm_autosmp enabled\n");
	} else {
		cancel_delayed_work_sync(&msm_asmp_work);
#if CONFIG_NR_CPUS > 2
		for (cpu = 1; cpu < nr_cpu_ids; cpu++)
#endif
			asmp_cpu_up(cpu);
		pr_info(ASMP_TAG"msm_autosmp disabled\n");
	}
	return ret;
}

static struct kernel_param_ops module_ops = {
	.set = set_enabled,
	.get = param_get_bool,
};

module_param_cb(enabled, &module_ops, &enabled, 0644);
MODULE_PARM_DESC(enabled, "hotplug cpu cores based on demand");

/***************************** SYSFS START *****************************/
struct kobject *msm_asmp_kobject;

#define show_one(file_name, object)					\
static ssize_t show_##file_name						\
(struct kobject *kobj, struct attribute *attr, char *buf)		\
{									\
	return sprintf(buf, "%u\n", msm_asmp_tuners_ins.object);	\
}
show_one(delay, delay);
show_one(pause, pause);
show_one(scroff_single_core, scroff_single_core);
show_one(min_cpus, min_cpus);
show_one(max_cpus, max_cpus);
show_one(load_limit_up, load_limit_up);
show_one(load_limit_down, load_limit_down);
show_one(time_limit_up, time_limit_up);
show_one(time_limit_down, time_limit_down);

#define store_one(file_name, object)					\
static ssize_t store_##file_name					\
(struct kobject *a, struct attribute *b, const char *buf, size_t count)	\
{									\
	unsigned int input;						\
	int ret;							\
	ret = sscanf(buf, "%u", &input);				\
	if (ret != 1)							\
		return -EINVAL;						\
	msm_asmp_tuners_ins.object = input;				\
	return count;							\
}									\
define_one_global_rw(file_name);
store_one(delay, delay);
store_one(pause, pause);
store_one(scroff_single_core, scroff_single_core);
store_one(max_cpus, max_cpus);
store_one(min_cpus, min_cpus);
store_one(load_limit_up, load_limit_up);
store_one(load_limit_down, load_limit_down);
store_one(time_limit_up, time_limit_up);
store_one(time_limit_down, time_limit_down);


static struct attribute *msm_asmp_attributes[] = {
	&delay.attr,
	&pause.attr,
	&scroff_single_core.attr,
	&min_cpus.attr,
	&max_cpus.attr,
	&load_limit_up.attr,
	&load_limit_down.attr,
	&time_limit_up.attr,
	&time_limit_down.attr,
	NULL
};

static struct attribute_group msm_asmp_attr_group = {
	.attrs = msm_asmp_attributes,
	.name = "conf",
};
#if STATS
static ssize_t show_times_hotplugged(struct kobject *a, 
					struct attribute *b, char *buf) {
	ssize_t len = 0;
	int cpu = 0;

	for_each_possible_cpu(cpu) {
		len += sprintf(buf + len, "%i %llu\n", cpu, 
			per_cpu(msm_asmp_cpudata, cpu).times_hotplugged);
	}
	return len;
}
define_one_global_ro(times_hotplugged);

static struct attribute *msm_asmp_stats_attributes[] = {
	&times_hotplugged.attr,
	NULL
};

static struct attribute_group msm_asmp_stats_attr_group = {
	.attrs = msm_asmp_stats_attributes,
	.name = "stats",
};
#endif
/****************************** SYSFS END ******************************/

static int __init msm_asmp_init(void) {
	int cpu, rc, err = 0;

	rq_wq = create_singlethread_workqueue("rq_stats");
	BUG_ON(!rq_wq);
	INIT_WORK(&rq_info.def_timer_work, rq_work_fn);
	spin_lock_init(&rq_lock);
	rq_info.rq_poll_jiffies = DEFAULT_RQ_POLL_JIFFIES;
	rq_info.def_timer_jiffies = DEFAULT_DEF_TIMER_JIFFIES;
	rq_info.def_start_time = ktime_to_ns(ktime_get());
	rq_info.rq_poll_last_jiffy = 0;
	rq_info.def_timer_last_jiffy = 0;
	rq_info.hotplug_disabled = 0;
	rq_info.init = 1;

	was_paused = true;
	last_time = ktime_to_ms(ktime_get());
	for_each_possible_cpu(cpu) {
		mutex_init(&(per_cpu(msm_asmp_cpudata, cpu).hotplug_mutex));
		per_cpu(msm_asmp_cpudata, cpu).online = true;
#if STATS
		per_cpu(msm_asmp_cpudata, cpu).times_hotplugged = 0;
#endif
	}

	msm_asmp_workq = alloc_workqueue("asmp",
					WQ_UNBOUND | WQ_RESCUER | WQ_FREEZABLE, 1);
	if (!msm_asmp_workq)
		return -ENOMEM;
	INIT_DELAYED_WORK(&msm_asmp_work, msm_asmp_work_thread);
	if (enabled)
		queue_delayed_work(msm_asmp_workq, &msm_asmp_work,
				   msecs_to_jiffies(MSM_ASMP_STARTDELAY));

	register_early_suspend(&msm_asmp_early_suspend_handler);

	msm_asmp_kobject = kobject_create_and_add("msm_autosmp", kernel_kobj);
	if (msm_asmp_kobject) {
		rc = sysfs_create_group(msm_asmp_kobject,
					&msm_asmp_attr_group);
		if (rc)
			pr_warn(ASMP_TAG"sysfs: ERROR, could not create sysfs group");
#if STATS
		rc = sysfs_create_group(msm_asmp_kobject,
					&msm_asmp_stats_attr_group);
		if (rc)
			pr_warn(ASMP_TAG"sysfs: ERROR, could not create sysfs stats group");
#endif
	} else
		pr_warn(ASMP_TAG"sysfs: ERROR, could not create sysfs kobj");

	pr_info(ASMP_TAG"%s init complete.", __func__);
	return err;
}
late_initcall(msm_asmp_init);
