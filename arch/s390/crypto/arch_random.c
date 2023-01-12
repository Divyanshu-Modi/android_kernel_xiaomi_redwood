// SPDX-License-Identifier: GPL-2.0
/*
 * s390 arch random implementation.
 *
 * Copyright IBM Corp. 2017, 2020
 * Author(s): Harald Freudenberger
 */

#include <linux/kernel.h>
#include <linux/atomic.h>
#include <linux/random.h>
#include <linux/static_key.h>
#include <asm/cpacf.h>

DEFINE_STATIC_KEY_FALSE(s390_arch_random_available);

atomic64_t s390_arch_random_counter = ATOMIC64_INIT(0);
EXPORT_SYMBOL(s390_arch_random_counter);

#define ARCH_REFILL_TICKS (HZ/2)
#define ARCH_PRNG_SEED_SIZE 32
#define ARCH_RNG_BUF_SIZE 2048

static DEFINE_SPINLOCK(arch_rng_lock);
static u8 *arch_rng_buf;
static unsigned int arch_rng_buf_idx;

static void arch_rng_refill_buffer(struct work_struct *);
static DECLARE_DELAYED_WORK(arch_rng_work, arch_rng_refill_buffer);

bool s390_arch_random_generate(u8 *buf, unsigned int nbytes)
{
	/* max hunk is ARCH_RNG_BUF_SIZE */
	if (nbytes > ARCH_RNG_BUF_SIZE)
		return false;

	/* lock rng buffer */
	if (!spin_trylock(&arch_rng_lock))
		return false;

	/* try to resolve the requested amount of bytes from the buffer */
	arch_rng_buf_idx -= nbytes;
	if (arch_rng_buf_idx < ARCH_RNG_BUF_SIZE) {
		memcpy(buf, arch_rng_buf + arch_rng_buf_idx, nbytes);
		atomic64_add(nbytes, &s390_arch_random_counter);
		spin_unlock(&arch_rng_lock);
		return true;
	}

	/* not enough bytes in rng buffer, refill is done asynchronously */
	spin_unlock(&arch_rng_lock);

	return false;
}
EXPORT_SYMBOL(s390_arch_random_generate);

static void arch_rng_refill_buffer(struct work_struct *unused)
{
	unsigned int delay = ARCH_REFILL_TICKS;

	spin_lock(&arch_rng_lock);
	if (arch_rng_buf_idx > ARCH_RNG_BUF_SIZE) {
		/* buffer is exhausted and needs refill */
		u8 seed[ARCH_PRNG_SEED_SIZE];
		u8 prng_wa[240];
		/* fetch ARCH_PRNG_SEED_SIZE bytes of entropy */
		cpacf_trng(NULL, 0, seed, sizeof(seed));
		/* blow this entropy up to ARCH_RNG_BUF_SIZE with PRNG */
		memset(prng_wa, 0, sizeof(prng_wa));
		cpacf_prno(CPACF_PRNO_SHA512_DRNG_SEED,
			   &prng_wa, NULL, 0, seed, sizeof(seed));
		cpacf_prno(CPACF_PRNO_SHA512_DRNG_GEN,
			   &prng_wa, arch_rng_buf, ARCH_RNG_BUF_SIZE, NULL, 0);
		arch_rng_buf_idx = ARCH_RNG_BUF_SIZE;
	}
	delay += (ARCH_REFILL_TICKS * arch_rng_buf_idx) / ARCH_RNG_BUF_SIZE;
	spin_unlock(&arch_rng_lock);

	/* kick next check */
	queue_delayed_work(system_long_wq, &arch_rng_work, delay);
}

static int __init s390_arch_random_init(void)
{
	/* all the needed PRNO subfunctions available ? */
	if (cpacf_query_func(CPACF_PRNO, CPACF_PRNO_TRNG) &&
	    cpacf_query_func(CPACF_PRNO, CPACF_PRNO_SHA512_DRNG_GEN)) {

		/* alloc arch random working buffer */
		arch_rng_buf = kmalloc(ARCH_RNG_BUF_SIZE, GFP_KERNEL);
		if (!arch_rng_buf)
			return -ENOMEM;

		/* kick worker queue job to fill the random buffer */
		queue_delayed_work(system_long_wq,
				   &arch_rng_work, ARCH_REFILL_TICKS);

		/* enable arch random to the outside world */
		static_branch_enable(&s390_arch_random_available);
	}

	return 0;
}
arch_initcall(s390_arch_random_init);
