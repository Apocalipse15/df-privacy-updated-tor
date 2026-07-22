/* Copyright (c) 2017-2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file scheduler_up_privacy_vanilla.c
 * @brief Differential Private Implementation of Vanilla Scheduler
 *
 **/

#include "core/or/or.h"
#include "app/config/config.h"
#define CHANNEL_OBJECT_PRIVATE
#include "core/or/channel.h"
#define SCHEDULER_PRIVATE
#include "core/or/scheduler.h"
#include "feature/nodelist/nodelist.h"
#include "feature/nodelist/node_select.h"
#include "core/or/extend_info_st.h"
#include "core/or/extendinfo.h"
#include "core/or/cell_st.h"                
#include "lib/crypt_ops/crypto_rand.h"       
#include "core/or/channeltls.h"          

#include "lib/dprivacy/dp_mech.h"

/*****************************************************************************
 * Differential Privacy Logics
 *****************************************************************************/
static monotime_t scheduler_last_run;
static unsigned int scheduler_run_interval;

static double priv_epsilon = 0.0;
static dp_mechanism_t dp_mechanism = DP_MECHANISM_UNKNOWN;
static char *prob_dp_mechanism = "0.125_0.125_0.125_0.125_0.125_0.125_0.125_0.125"; // Default probabilities for the 8 mechanisms in the hybrid_prob_mechanism

static double fake_priv_epsilon = 0.0;
static dp_mechanism_t fake_dp_mechanism = DP_MECHANISM_UNKNOWN;
static char *fake_prob_dp_mechanism = "0.125_0.125_0.125_0.125_0.125_0.125_0.125_0.125"; // Default probabilities for the 8 mechanisms in the hybrid_prob_mechanism


/** Channels we manually opened for dummy cell injection */
static smartlist_t *dp_created_channels = NULL;


static scheduler_jitter_t sched_vanilla_jitter = {.target =
                                                      PRIV_SCHED_DEFAULT_JITTER,
                                                  .max = PRIV_SCHED_MAX_JITTER,
                                                  .min = PRIV_SCHED_MIN_JITTER};

static scheduler_jitter_t sched_fake_jitter = {.target =
                                                      PRIV_SCHED_DEFAULT_JITTER,
                                                  .max = PRIV_SCHED_MAX_JITTER,
                                                  .min = PRIV_SCHED_MIN_JITTER};                                                

/**
 * Sets the run_interval based on a differential private algorithm.
 */
static void
privacy_up_vanilla_scheduler_set_next_run(void)
{
  scheduler_run_interval =
      dp_generate_int(sched_vanilla_jitter.min, sched_vanilla_jitter.max,
                      sched_vanilla_jitter.target, priv_epsilon, dp_mechanism, prob_dp_mechanism);
  log_debug(LD_SCHED,
            "[DP_VANILLA] Next scheduler run interval is %d ms",
            scheduler_run_interval);
}

/*****************************************************************************
 * Other internal data
 *****************************************************************************/

/* Maximum cells to flush in a single call to channel_flush_some_cells(); */
#define MAX_FLUSH_CELLS 1000

/*****************************************************************************
 * Externally called function implementations
 *****************************************************************************/

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


static void 
privacy_up_vanilla_scheduler_on_new_options(void)
{
  const or_options_t *options = get_options();

  dp_mechanism = string_to_dp_mechanism_type(options->PrivSchedulerDistribution);
  priv_epsilon = options->PrivSchedulerEpsilon;

  sched_vanilla_jitter.target = options->PrivSchedulerTargetJitter;
  sched_vanilla_jitter.max = options->PrivSchedulerMaxJitter;
  sched_vanilla_jitter.min = options->PrivSchedulerMinJitter;
  prob_dp_mechanism = options->PrivDistributionProbabilities;

  fake_dp_mechanism = string_to_dp_mechanism_type(options->PrivFakeChannelDistribution);
  fake_priv_epsilon = options->PrivFakeChannelEpsilon;
  fake_prob_dp_mechanism = options->PrivFakeChannelProbabilities;
  sched_fake_jitter.target = options->PrivFakeChannelTargetJitter;
  sched_fake_jitter.max = options->PrivFakeChannelMaxJitter;
  sched_fake_jitter.min = options->PrivFakeChannelMinJitter;

  log_debug(LD_SCHED,
            "[PRIV_VANILLA] Scheduler distribution: %s, epsilon: %.2f, "
            "jitter target: %d, max: %d, min: %d",
            dp_mechanism_type_to_string(dp_mechanism), priv_epsilon,
            sched_vanilla_jitter.target, sched_vanilla_jitter.max,
            sched_vanilla_jitter.min);
}

static void
privacy_up_vanilla_scheduler_send_dummy_cells(void)
{
  log_warn(LD_SCHED, "LOG HERE");
  smartlist_t *cp = get_channels_pending();

  if (smartlist_len(cp) == 0) {
    log_warn(LD_SCHED, "[DP_VANILLA] No pending channels to send dummy cells to.");
  }
  log_warn(LD_SCHED, "[DP_VANILLA] Sending dummy cells to %d pending channels.", smartlist_len(cp));

  if (dp_created_channels) {
    SMARTLIST_FOREACH_BEGIN(dp_created_channels, channel_t *, dc) {
      if (dc->state == CHANNEL_STATE_OPEN) {
        int cells_to_send = dp_generate_int(sched_fake_jitter.min, sched_fake_jitter.max,
                    sched_fake_jitter.target, fake_priv_epsilon, fake_dp_mechanism, fake_prob_dp_mechanism);
        
        log_warn(LD_SCHED, "[DP] Sending %d dummy cells on created channel %" PRIu64, cells_to_send, dc->global_identifier);

        for (int i = 0; i < cells_to_send; i++) {
          /* Send dummy cell */
          cell_t dummy;
          memset(&dummy, 0, sizeof(cell_t));
          dummy.command = CELL_DUMMY;
          dummy.circ_id = 0;
          crypto_fast_rng_getbytes(get_thread_fast_rng(),
                                  dummy.payload,
                                  sizeof(dummy.payload));

          if (dc->write_cell) {
              dc->write_cell(dc, &dummy);
              log_warn(LD_SCHED, "[DP] Sent CELL_DUMMY on created channel "
                                "%" PRIu64, dc->global_identifier);
          }
        }
        /* Mark for close after sending */
            channel_mark_for_close(dc);
            log_warn(LD_SCHED, "[DP] Marked created channel %" PRIu64
                              " for close", dc->global_identifier);
        }
    } SMARTLIST_FOREACH_END(dc);

    smartlist_clear(dp_created_channels);
  }
  

  SMARTLIST_FOREACH_BEGIN(cp, channel_t *, chan) {
    if(dp_generate_bool(true, fake_priv_epsilon)) {
      log_warn(LD_SCHED, "[DP] Decided to create a new channel for dummy cell injection.");
    } else {
      log_warn(LD_SCHED, "[DP] Decided NOT to create a new channel for dummy cell injection.");
      continue;
    }
    tor_addr_t remote_addr;
    char addr_buf[TOR_ADDR_BUF_LEN];

    if (!channel_get_addr_if_possible(chan, &remote_addr)) {
        strlcpy(addr_buf, "<no address>", sizeof(addr_buf));
        continue;
    }
    tor_addr_to_str(addr_buf, &remote_addr, sizeof(addr_buf), 0);

    if (!chan->is_incoming || chan->state != CHANNEL_STATE_OPEN)
        continue;

    const node_t *node = node_get_by_id(chan->identity_digest);
    if (!node) continue;

    extend_info_t *ei = extend_info_from_node(node, 1, 0);
    if (!ei) continue;

    const ed25519_public_key_t *ed_id =
        ed25519_public_key_is_zero(&chan->ed25519_identity)
            ? NULL : &chan->ed25519_identity;

    channel_t *new_chan = channel_tls_connect(
        &ei->orports[0].addr,
        ei->orports[0].port,
        chan->identity_digest,
        ed_id
    );
    extend_info_free(ei);

    if (!new_chan) {
        log_warn(LD_SCHED, "[DP] Failed to open channel to %s", addr_buf);
        continue;
    }

    /* Track it for next iteration */
    smartlist_add(dp_created_channels, new_chan);
    log_warn(LD_SCHED, "[DP] Created channel %" PRIu64 " to %s, "
                       "will send dummy next iteration.",
             new_chan->global_identifier, addr_buf);

  } SMARTLIST_FOREACH_END(chan);

  /*channel_tls_connect(const tor_addr_t *addr, uint16_t port,
                    const char *id_digest,
                    const ed25519_public_key_t *ed_id)*/
}

static void
privacy_up_vanilla_scheduler_init(void)
{
  if (!dp_created_channels) {
    dp_created_channels = smartlist_new();
  }
  monotime_get(&scheduler_last_run);
  privacy_up_vanilla_scheduler_on_new_options();
  privacy_up_vanilla_scheduler_set_next_run();
}

/** Re-trigger the scheduler in a way safe to use from the callback */
static void
privacy_up_vanilla_scheduler_schedule(void)
{           
  struct monotime_t now;
  struct timeval next_run;
  int64_t diff;

  privacy_up_vanilla_scheduler_send_dummy_cells();

  if (!have_work()) {    
    return;
  }

  monotime_get(&now);
  diff = monotime_diff_msec(&scheduler_last_run, &now);
  if (diff < 0) {
    diff = 0;
  } 

  if (diff < scheduler_run_interval) {
    next_run.tv_sec = 0;
    next_run.tv_usec = (int) ((scheduler_run_interval - diff) * 1000);
    scheduler_ev_add(&next_run);
  } else {
    scheduler_ev_active();
  }
  scheduler_last_run = now;
  privacy_up_vanilla_scheduler_set_next_run();
}


static void
privacy_up_vanilla_scheduler_run(void)
{
  int n_cells, n_chans_before, n_chans_after;
  ssize_t flushed, flushed_this_time;
  smartlist_t *cp = get_channels_pending();
  smartlist_t *to_readd = NULL;
  channel_t *chan = NULL;

  log_debug(LD_SCHED, "We have a chance to run the scheduler");

  n_chans_before = smartlist_len(cp);

  while (smartlist_len(cp) > 0) {
    /* Pop off a channel */
    chan = smartlist_pqueue_pop(cp,
                                scheduler_compare_channels,
                                offsetof(channel_t, sched_heap_idx));
    IF_BUG_ONCE(!chan) {
      /* Some-freaking-how a NULL got into the channels_pending. That should
       * never happen, but it should be harmless to ignore it and keep looping.
       */
      continue;
    }

    /* Figure out how many cells we can write */
    n_cells = channel_num_cells_writeable(chan);
    if (n_cells > 0) {
      log_debug(LD_SCHED,
                "Scheduler saw pending channel %"PRIu64 " at %p with "
                "%d cells writeable",
                (chan->global_identifier), chan, n_cells);

      flushed = 0;
      while (flushed < n_cells) {
        flushed_this_time =
          channel_flush_some_cells(chan,
                        MIN(MAX_FLUSH_CELLS, (size_t) n_cells - flushed));
        if (flushed_this_time <= 0) break;
        flushed += flushed_this_time;
      }

      if (flushed < n_cells) {
        /* We ran out of cells to flush */
        scheduler_set_channel_state(chan, SCHED_CHAN_WAITING_FOR_CELLS);
      } else {
        /* The channel may still have some cells */
        if (channel_more_to_flush(chan)) {
        /* The channel goes to either pending or waiting_to_write */
          if (channel_num_cells_writeable(chan) > 0) {
            /* Add it back to pending later */
            if (!to_readd) to_readd = smartlist_new();
            smartlist_add(to_readd, chan);
            log_debug(LD_SCHED,
                      "Channel %"PRIu64 " at %p "
                      "is still pending",
                      (chan->global_identifier),
                      chan);
          } else {
            /* It's waiting to be able to write more */
            scheduler_set_channel_state(chan, SCHED_CHAN_WAITING_TO_WRITE);
          }
        } else {
          /* No cells left; it can go to idle or waiting_for_cells */
          if (channel_num_cells_writeable(chan) > 0) {
            /*
             * It can still accept writes, so it goes to
             * waiting_for_cells
             */
            scheduler_set_channel_state(chan, SCHED_CHAN_WAITING_FOR_CELLS);
          } else {
            /*
             * We exactly filled up the output queue with all available
             * cells; go to idle.
             */
            scheduler_set_channel_state(chan, SCHED_CHAN_IDLE);
          }
        }
      }

      log_debug(LD_SCHED,
                "Scheduler flushed %d cells onto pending channel "
                "%"PRIu64 " at %p",
                (int)flushed, (chan->global_identifier),
                chan);
    } else {
      log_info(LD_SCHED,
               "Scheduler saw pending channel %"PRIu64 " at %p with "
               "no cells writeable",
               (chan->global_identifier), chan);
      /* Put it back to WAITING_TO_WRITE */
      scheduler_set_channel_state(chan, SCHED_CHAN_WAITING_TO_WRITE);
    }
  }

  /* Readd any channels we need to */
  if (to_readd) {
    SMARTLIST_FOREACH_BEGIN(to_readd, channel_t *, readd_chan) {
      scheduler_set_channel_state(readd_chan, SCHED_CHAN_PENDING);
      smartlist_pqueue_add(cp,
                           scheduler_compare_channels,
                           offsetof(channel_t, sched_heap_idx),
                           readd_chan);
    } SMARTLIST_FOREACH_END(readd_chan);
    smartlist_free(to_readd);
  }

  n_chans_after = smartlist_len(cp);
  log_debug(LD_SCHED, "Scheduler handled %d of %d pending channels",
            n_chans_before - n_chans_after, n_chans_before);
}

/* Stores the vanilla scheduler function pointers. */
static scheduler_t privacy_up_vanilla_scheduler = {
  .type = SCHEDULER_UP_PRIV_VANILLA,
  .free_all = NULL,
  .on_channel_free = NULL,
  .init = privacy_up_vanilla_scheduler_init,
  .on_new_consensus = NULL,
  .schedule = privacy_up_vanilla_scheduler_schedule,
  .run = privacy_up_vanilla_scheduler_run,
  .on_new_options = privacy_up_vanilla_scheduler_on_new_options,
};

scheduler_t *
get_privacy_up_vanilla_scheduler(void)
{
  return &privacy_up_vanilla_scheduler;
}
