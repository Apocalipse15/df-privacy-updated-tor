/* Copyright (c) 2017-2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file scheduler_privacy_kist.c
 * @brief Implementation of Privacy-Enhanced KIST Scheduler
 *
 * PrivKIST Scheduler is an extension of the KIST Scheduler
 * (scheduler_kist) where jitter may be applied based on mathematical distributions. 
 * This way, traffic analysis and correlation gets harder to
 * deanonimyze users' information.addressmap_entry_source_bitfield_t
 *
 * This solutions gives total control over to the host of the relay, with a
 * fully customizable implementation. The host may set the targetted jitter,
 * the interval of accepted jitter inserted by the scheduler. Also, the host
 * can choose the mathematical distribuition and the value of epsilon. 
 * The higher the epsilon, more jitter is applyed.
 **/

#define SCHEDULER_KIST_PRIVATE

#include "core/or/or.h"
#include "lib/buf/buffers.h"
#include "app/config/config.h"
#include "core/mainloop/connection.h"
#include "feature/nodelist/networkstatus.h"
#include "feature/relay/routermode.h"
#define CHANNEL_OBJECT_PRIVATE
#include "core/or/channel.h"
#include "core/or/channeltls.h"
#define SCHEDULER_PRIVATE
#include "core/or/scheduler.h"
#include "lib/math/fp.h"

#include "core/or/or_connection_st.h"

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_KIST_SUPPORT
/* Kernel interface needed for KIST. */
#  include <netinet/tcp.h>
#  include <linux/sockios.h>
#endif /* HAVE_KIST_SUPPORT */

#include "lib/dprivacy/dp_mech.h"

/*****************************************************************************
 * Differential Privacy Logic
 *****************************************************************************/

static monotime_t sched_last_run;
static unsigned int priv_sched_next_run;

static double priv_epsilon = 0.0;
static dp_mechanism_t dp_mechanism = DP_MECHANISM_UNKNOWN;

static scheduler_jitter_t sched_kist_jitter = {.target =
                                                   PRIV_SCHED_DEFAULT_JITTER,
                                               .max = PRIV_SCHED_MAX_JITTER,
                                               .min = PRIV_SCHED_MIN_JITTER};

/**
 * Sets the run_interval based on a differential private algorithm.
 */
static void
privacy_kist_scheduler_set_next_run(unsigned int *sched_interval) 
{
  priv_sched_next_run =
      dp_generate_int(sched_kist_jitter.min, sched_kist_jitter.max,
                      sched_kist_jitter.target, priv_epsilon, dp_mechanism);
  log_debug(LD_SCHED, "Next run interval set to %d ms", *sched_interval);
}

/*****************************************************************************
 * Data structures and supporting functions
 *****************************************************************************/

/* Socket_table hash table stuff. The socket_table keeps track of per-socket
 * limit information imposed by kist and used by kist. */

static uint32_t
socket_table_ent_hash(const socket_table_ent_t *ent)
{
  return (uint32_t)ent->chan->global_identifier;
}

static unsigned
socket_table_ent_eq(const socket_table_ent_t *a, const socket_table_ent_t *b)
{
  return a->chan == b->chan;
}

typedef HT_HEAD(socket_table_s, socket_table_ent_t) socket_table_t;

static socket_table_t socket_table = HT_INITIALIZER();

HT_PROTOTYPE(socket_table_s, socket_table_ent_t, node, socket_table_ent_hash,
             socket_table_ent_eq);

/* outbuf_table hash table stuff. The outbuf_table keeps track of which
 * channels have data sitting in their outbuf so the kist scheduler can force
 * a write from outbuf to kernel periodically during a run and at the end of a
 * run. */

typedef struct outbuf_table_ent_t {
  HT_ENTRY(outbuf_table_ent_t) node;
  channel_t *chan;
} outbuf_table_ent_t;

static uint32_t
outbuf_table_ent_hash(const outbuf_table_ent_t *ent)
{
  return (uint32_t)ent->chan->global_identifier;
}

static unsigned
outbuf_table_ent_eq(const outbuf_table_ent_t *a, const outbuf_table_ent_t *b)
{
  return a->chan->global_identifier == b->chan->global_identifier;
}

HT_PROTOTYPE(outbuf_table_s, outbuf_table_ent_t, node, outbuf_table_ent_hash,
             outbuf_table_ent_eq);
//HT_GENERATE2(outbuf_table_s, outbuf_table_ent_t, node, outbuf_table_ent_hash,
//             outbuf_table_ent_eq, 0.6, tor_reallocarray, tor_free_);

/*****************************************************************************
 * Other internal data
 *****************************************************************************/

/* This is a factor for the extra_space calculation in kist per-socket limits.
 * It is the number of extra congestion windows we want to write to the kernel.
 */
static double sock_buf_size_factor = 1.0;

/*****************************************************************************
 * Internally called function implementations
 *****************************************************************************/

/* Little helper function to get the length of a channel's output buffer */
static inline size_t
channel_outbuf_length(channel_t *chan)
{
  tor_assert(chan);
  /* In theory, this can not happen because we can not scheduler a channel
   * without a connection that has its outbuf initialized. Just in case, bug
   * on this so we can understand a bit more why it happened. */
  if (SCHED_BUG(BASE_CHAN_TO_TLS(chan)->conn == NULL, chan)) {
    return 0;
  }
  return buf_datalen(TO_CONN(BASE_CHAN_TO_TLS(chan)->conn)->outbuf);
}

/* Little helper function for HT_FOREACH_FN. */
static int
each_channel_write_to_kernel(outbuf_table_ent_t *ent, void *data)
{
  (void) data; /* Make compiler happy. */
  channel_write_to_kernel(ent->chan);
  return 0; /* Returning non-zero removes the element from the table. */
}

/* Free the given outbuf table entry ent. */
static int
free_outbuf_info_by_ent(outbuf_table_ent_t *ent, void *data)
{
  (void) data; /* Make compiler happy. */
  log_debug(LD_SCHED, "Freeing outbuf table entry from chan=%" PRIu64,
            ent->chan->global_identifier);
  tor_free(ent);
  return 1; /* So HT_FOREACH_FN will remove the element */
}

/* Free the given socket table entry ent. */
static int
free_socket_info_by_ent(socket_table_ent_t *ent, void *data)
{
  (void) data; /* Make compiler happy. */
  log_debug(LD_SCHED, "Freeing socket table entry from chan=%" PRIu64,
            ent->chan->global_identifier);
  tor_free(ent);
  return 1; /* So HT_FOREACH_FN will remove the element */
}

/* Clean up socket_table. Probably because the KIST sched impl is going away */
static void
free_all_socket_info(void)
{
  HT_FOREACH_FN(socket_table_s, &socket_table, free_socket_info_by_ent, NULL);
  HT_CLEAR(socket_table_s, &socket_table);
}

static socket_table_ent_t *
socket_table_search(socket_table_t *table, const channel_t *chan)
{
  socket_table_ent_t search, *ent = NULL;
  search.chan = chan;
  ent = HT_FIND(socket_table_s, table, &search);
  return ent;
}

/* Free a socket entry in table for the given chan. */
static void
free_socket_info_by_chan(socket_table_t *table, const channel_t *chan)
{
  socket_table_ent_t *ent = NULL;
  ent = socket_table_search(table, chan);
  if (!ent)
    return;
  log_debug(LD_SCHED, "scheduler free socket info for chan=%" PRIu64,
            chan->global_identifier);
  HT_REMOVE(socket_table_s, table, ent);
  free_socket_info_by_ent(ent, NULL);
}


/* Given a socket that isn't in the table, add it.
 * Given a socket that is in the table, re-init values that need init-ing
 * every scheduling run
 */
static void
init_socket_info(socket_table_t *table, const channel_t *chan)
{
  socket_table_ent_t *ent = NULL;
  ent = socket_table_search(table, chan);
  if (!ent) {
    log_debug(LD_SCHED, "scheduler init socket info for chan=%" PRIu64,
              chan->global_identifier);
    ent = tor_malloc_zero(sizeof(*ent));
    ent->chan = chan;
    HT_INSERT(socket_table_s, table, ent);
  }
  ent->written = 0;
}

/* Add chan to the outbuf table if it isn't already in it. If it is, then don't
 * do anything */
static void
outbuf_table_add(outbuf_table_t *table, channel_t *chan)
{
  outbuf_table_ent_t search, *ent;
  search.chan = chan;
  ent = HT_FIND(outbuf_table_s, table, &search);
  if (!ent) {
    log_debug(LD_SCHED, "scheduler init outbuf info for chan=%" PRIu64,
              chan->global_identifier);
    ent = tor_malloc_zero(sizeof(*ent));
    ent->chan = chan;
    HT_INSERT(outbuf_table_s, table, ent);
  }
}

static void
outbuf_table_remove(outbuf_table_t *table, channel_t *chan)
{
  outbuf_table_ent_t search, *ent;
  search.chan = chan;
  ent = HT_FIND(outbuf_table_s, table, &search);
  if (ent) {
    HT_REMOVE(outbuf_table_s, table, ent);
    free_outbuf_info_by_ent(ent, NULL);
  }
}

/* Set the scheduler running interval. */
static void
set_scheduler_run_interval(void)
{
  unsigned int old_sched_run_interval = priv_sched_next_run;
  privacy_kist_scheduler_set_next_run(&priv_sched_next_run);
  if (old_sched_run_interval != priv_sched_next_run) {
    log_info(LD_SCHED, "Scheduler PRIV_KIST changing its running interval "
                       "from %" PRId32 " to %" PRId32,
             old_sched_run_interval, priv_sched_next_run);
  }
}

/* Return true iff the channel hasn't hit its kist-imposed write limit yet */
static int
socket_can_write(socket_table_t *table, const channel_t *chan)
{
  socket_table_ent_t *ent = NULL;
  ent = socket_table_search(table, chan);
  if (SCHED_BUG(!ent, chan)) {
    return 1; // Just return true, saying that kist wouldn't limit the socket
  }

  /* We previously calculated a write limit for this socket. In the below
   * calculation, first determine how much room is left in bytes. Then divide
   * that by the amount of space a cell takes. If there's room for at least 1
   * cell, then KIST will allow the socket to write. */
  int64_t kist_limit_space =
    (int64_t) (ent->limit - ent->written) /
    (CELL_MAX_NETWORK_SIZE + TLS_PER_CELL_OVERHEAD);
  return kist_limit_space > 0;
}

/* Update the channel's socket kernel information. */
static void
update_socket_info(socket_table_t *table, const channel_t *chan)
{
  socket_table_ent_t *ent = NULL;
  ent = socket_table_search(table, chan);
  if (SCHED_BUG(!ent, chan)) {
    return; // Whelp. Entry didn't exist for some reason so nothing to do.
  }
  update_socket_info_impl(ent);
  log_debug(LD_SCHED, "chan=%" PRIu64 " updated socket info, limit: %" PRIu64
                      ", cwnd: %" PRIu32 ", unacked: %" PRIu32
                      ", notsent: %" PRIu32 ", mss: %" PRIu32,
            ent->chan->global_identifier, ent->limit, ent->cwnd, ent->unacked,
            ent->notsent, ent->mss);
}

/* Increment the channel's socket written value by the number of bytes. */
static void
update_socket_written(socket_table_t *table, channel_t *chan, size_t bytes)
{
  socket_table_ent_t *ent = NULL;
  ent = socket_table_search(table, chan);
  if (SCHED_BUG(!ent, chan)) {
    return; // Whelp. Entry didn't exist so nothing to do.
  }

  log_debug(LD_SCHED, "chan=%" PRIu64 " wrote %lu bytes, old was %" PRIi64,
            chan->global_identifier, (unsigned long) bytes, ent->written);

  ent->written += bytes;
}


/* Return true iff the scheduler has work to perform. */
static int
have_work(void)
{
  smartlist_t *cp = get_channels_pending();
  IF_BUG_ONCE(!cp) {
    return 0; // channels_pending doesn't exist so... no work?
  }
  return smartlist_len(cp) > 0;
}

/* Function of the scheduler interface: free_all() */
static void
kist_free_all(void)
{
  free_all_socket_info();
}

/* Function of the scheduler interface: on_channel_free() */
static void
kist_on_channel_free_fn(const channel_t *chan)
{
  free_socket_info_by_chan(&socket_table, chan);
}

/* Function of the scheduler interface: on_new_consensus() */
static void
kist_scheduler_on_new_consensus(void)
{
  set_scheduler_run_interval();
}

/* Function of the scheduler interface: on_new_options() */
static void
privacy_kist_scheduler_on_new_options(void)
{
  sock_buf_size_factor = get_options()->KISTSockBufSizeFactor;

  const or_options_t *options = get_options();

  dp_mechanism = string_to_dp_mechanism_type(options->PrivSchedulerDistribution);
  priv_epsilon = options->PrivSchedulerEpsilon;

  sched_kist_jitter.target = options->PrivSchedulerTargetJitter;
  sched_kist_jitter.max = options->PrivSchedulerMaxJitter;
  sched_kist_jitter.min = options->PrivSchedulerMinJitter;

  log_debug(LD_SCHED,
            "[PRIV_KIST] Scheduler distribution: %s, epsilon: %.2f, "
            "jitter target: %d, max: %d, min: %d",
            dp_mechanism_type_to_string(dp_mechanism), priv_epsilon,
            sched_kist_jitter.target, sched_kist_jitter.max,
            sched_kist_jitter.min);

  /* Calls kist_scheduler_run_interval which calls get_options(). */
  set_scheduler_run_interval();
}

/* Function of the scheduler interface: init() */
static void
privacy_kist_scheduler_init(void)
{
  /* When initializing the scheduler, the last run could be 0 because it is
   * declared static or a value in the past that was set when it was last
   * used. In both cases, we want to initialize it to now so we don't risk
   * using the value 0 which doesn't play well with our monotonic time
   * interface.
   *
   * One side effect is that the first scheduler run will be at the next tick
   * that is in now + 10 msec (KIST_SCHED_RUN_INTERVAL_DEFAULT) by default. */
  monotime_get(&sched_last_run);

  privacy_kist_scheduler_on_new_options();
  IF_BUG_ONCE(priv_sched_next_run == 0) {
    log_warn(LD_SCHED, "We are initing the Priv KIST scheduler and noticed the "
             "KISTSchedRunInterval is telling us to not use KIST. That's "
             "weird!");
    privacy_kist_scheduler_set_next_run(&priv_sched_next_run);
  }
}

/* Function of the scheduler interface: schedule() */
static void
privacy_kist_scheduler_schedule(void)
{
  struct monotime_t now;
  struct timeval next_run;
  int64_t diff;

  if (!have_work()) {
    return;
  }
  monotime_get(&now);

  /* If time is really monotonic, we can never have now being smaller than the
   * last scheduler run. The scheduler_last_run at first is set to 0.
   * Unfortunately, not all platforms guarantee monotonic time so we log at
   * info level but don't make it more noisy. */
  diff = monotime_diff_msec(&sched_last_run, &now);
  if (diff < 0) {
    log_info(LD_SCHED, "Monotonic time between now and last run of scheduler "
                       "is negative: %" PRId64 ". Setting diff to 0.", diff);
    diff = 0;
  }
  if (diff < priv_sched_next_run) {
    next_run.tv_sec = 0;
    /* Takes 1000 ms -> us. This will always be valid because diff can NOT be
     * negative and can NOT be bigger than sched_run_interval so values can
     * only go from 1000 usec (diff set to interval - 1) to 100000 usec (diff
     * set to 0) for the maximum allowed run interval (100ms). */
    next_run.tv_usec = (int) ((priv_sched_next_run - diff) * 1000);
    /* Re-adding an event reschedules it. It does not duplicate it. */
    scheduler_ev_add(&next_run);
  } else {
    scheduler_ev_active();
  }

  sched_last_run = now;
  privacy_kist_scheduler_set_next_run(&priv_sched_next_run);
}

/* Function of the scheduler interface: run() */
static void
privacy_kist_scheduler_run(void)
{
  /* Define variables */
  channel_t *chan = NULL; // current working channel
  /* The last distinct chan served in a sched loop. */
  channel_t *prev_chan = NULL;
  int flush_result; // temporarily store results from flush calls
  /* Channels to be re-adding to pending at the end */
  smartlist_t *to_readd = NULL;
  smartlist_t *cp = get_channels_pending();

  outbuf_table_t outbuf_table = HT_INITIALIZER();

  /* For each pending channel, collect new kernel information */
  SMARTLIST_FOREACH_BEGIN(cp, const channel_t *, pchan) {
      init_socket_info(&socket_table, pchan);
      update_socket_info(&socket_table, pchan);
  } SMARTLIST_FOREACH_END(pchan);

  log_debug(LD_SCHED, "Running the scheduler. %d channels pending",
            smartlist_len(cp));

  /* The main scheduling loop. Loop until there are no more pending channels */
  while (smartlist_len(cp) > 0) {
    /* get best channel */
    chan = smartlist_pqueue_pop(cp, scheduler_compare_channels,
                                offsetof(channel_t, sched_heap_idx));
    if (SCHED_BUG(!chan, NULL)) {
      /* Some-freaking-how a NULL got into the channels_pending. That should
       * never happen, but it should be harmless to ignore it and keep looping.
       */
      continue;
    }
    outbuf_table_add(&outbuf_table, chan);

    /* if we have switched to a new channel, consider writing the previous
     * channel's outbuf to the kernel. */
    if (!prev_chan) {
      prev_chan = chan;
    }
    if (prev_chan != chan) {
      if (channel_should_write_to_kernel(&outbuf_table, prev_chan)) {
        channel_write_to_kernel(prev_chan);
        outbuf_table_remove(&outbuf_table, prev_chan);
      }
      prev_chan = chan;
    }

    /* Only flush and write if the per-socket limit hasn't been hit */
    if (socket_can_write(&socket_table, chan)) {
      /* flush to channel queue/outbuf */
      flush_result = (int)channel_flush_some_cells(chan, 1); // 1 for num cells
      /* XXX: While flushing cells, it is possible that the connection write
       * fails leading to the channel to be closed which triggers a release
       * and free its entry in the socket table. And because of a engineering
       * design issue, the error is not propagated back so we don't get an
       * error at this point. So before we continue, make sure the channel is
       * open and if not just ignore it. See #23751. */
      if (!CHANNEL_IS_OPEN(chan)) {
        /* Channel isn't open so we put it back in IDLE mode. It is either
         * renegotiating its TLS session or about to be released. */
        scheduler_set_channel_state(chan, SCHED_CHAN_IDLE);
        continue;
      }
      /* flush_result has the # cells flushed */
      if (flush_result > 0) {
        update_socket_written(&socket_table, chan, flush_result *
                              (CELL_MAX_NETWORK_SIZE + TLS_PER_CELL_OVERHEAD));
      } else {
        /* XXX: This can happen because tor sometimes does flush in an
         * opportunistic way cells from the circuit to the outbuf so the
         * channel can end up here without having anything to flush nor needed
         * to write to the kernel. Hopefully we'll fix that soon but for now
         * we have to handle this case which happens kind of often. */
        log_debug(LD_SCHED,
                 "We didn't flush anything on a chan that we think "
                 "can write and wants to write. The channel's state is '%s' "
                 "and in scheduler state '%s'. We're going to mark it as "
                 "waiting_for_cells (as that's most likely the issue) and "
                 "stop scheduling it this round.",
                 channel_state_to_string(chan->state),
                 get_scheduler_state_string(chan->scheduler_state));
        scheduler_set_channel_state(chan, SCHED_CHAN_WAITING_FOR_CELLS);
        continue;
      }
    }

    /* Decide what to do with the channel now */

    if (!channel_more_to_flush(chan) &&
        !socket_can_write(&socket_table, chan)) {

      /* Case 1: no more cells to send, and cannot write */

      /*
       * You might think we should put the channel in SCHED_CHAN_IDLE. And
       * you're probably correct. While implementing KIST, we found that the
       * scheduling system would sometimes lose track of channels when we did
       * that. We suspect it has to do with the difference between "can't
       * write because socket/outbuf is full" and KIST's "can't write because
       * we've arbitrarily decided that that's enough for now." Sometimes
       * channels run out of cells at the same time they hit their
       * kist-imposed write limit and maybe the rest of Tor doesn't put the
       * channel back in pending when it is supposed to.
       *
       * This should be investigated again. It is as simple as changing
       * SCHED_CHAN_WAITING_FOR_CELLS to SCHED_CHAN_IDLE and seeing if Tor
       * starts having serious throughput issues. Best done in shadow/chutney.
       */
      scheduler_set_channel_state(chan, SCHED_CHAN_WAITING_FOR_CELLS);
    } else if (!channel_more_to_flush(chan)) {

      /* Case 2: no more cells to send, but still open for writes */

      scheduler_set_channel_state(chan, SCHED_CHAN_WAITING_FOR_CELLS);
    } else if (!socket_can_write(&socket_table, chan)) {

      /* Case 3: cells to send, but cannot write */

      /*
       * We want to write, but can't. If we left the channel in
       * channels_pending, we would never exit the scheduling loop. We need to
       * add it to a temporary list of channels to be added to channels_pending
       * after the scheduling loop is over. They can hopefully be taken care of
       * in the next scheduling round.
       */
      if (!to_readd) {
        to_readd = smartlist_new();
      }
      smartlist_add(to_readd, chan);
    } else {

      /* Case 4: cells to send, and still open for writes */

      scheduler_set_channel_state(chan, SCHED_CHAN_PENDING);
      if (!SCHED_BUG(chan->sched_heap_idx != -1, chan)) {
        smartlist_pqueue_add(cp, scheduler_compare_channels,
                             offsetof(channel_t, sched_heap_idx), chan);
      }
    }
  } /* End of main scheduling loop */

  /* Write the outbuf of any channels that still have data */
  HT_FOREACH_FN(outbuf_table_s, &outbuf_table, each_channel_write_to_kernel,
                NULL);
  /* We are done with it. */
  HT_FOREACH_FN(outbuf_table_s, &outbuf_table, free_outbuf_info_by_ent, NULL);
  HT_CLEAR(outbuf_table_s, &outbuf_table);

  log_debug(LD_SCHED, "len pending=%d, len to_readd=%d",
            smartlist_len(cp),
            (to_readd ? smartlist_len(to_readd) : -1));

  /* Re-add any channels we need to */
  if (to_readd) {
    SMARTLIST_FOREACH_BEGIN(to_readd, channel_t *, readd_chan) {
      scheduler_set_channel_state(readd_chan, SCHED_CHAN_PENDING);
      if (!smartlist_contains(cp, readd_chan)) {
        if (!SCHED_BUG(readd_chan->sched_heap_idx != -1, readd_chan)) {
          /* XXXX Note that the check above is in theory redundant with
           * the smartlist_contains check.  But let's make sure we're
           * not messing anything up, and leave them both for now. */
          smartlist_pqueue_add(cp, scheduler_compare_channels,
                             offsetof(channel_t, sched_heap_idx), readd_chan);
        }
      }
    } SMARTLIST_FOREACH_END(readd_chan);
    smartlist_free(to_readd);
  }


  //TODO: CHECK IF COMMENT HERE DOES SOMETHING: 
  //monotime_get(&scheduler_last_run);
}

/*****************************************************************************
 * Externally called function implementations not called through scheduler_t
 *****************************************************************************/

/* Stores the kist scheduler function pointers. */
static scheduler_t privacy_kist_scheduler = {
  .type = SCHEDULER_PRIV_KIST,
  .free_all = kist_free_all,
  .on_channel_free = kist_on_channel_free_fn,
  .init = privacy_kist_scheduler_init,
  .on_new_consensus = kist_scheduler_on_new_consensus,
  .schedule = privacy_kist_scheduler_schedule,
  .run = privacy_kist_scheduler_run,
  .on_new_options = privacy_kist_scheduler_on_new_options,
};

/* Return the KIST scheduler object. If it didn't exists, return a newly
 * allocated one but init() is not called. */
scheduler_t *
get_privacy_kist_scheduler(void)
{
  return &privacy_kist_scheduler;
}


