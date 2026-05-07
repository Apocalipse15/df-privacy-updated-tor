/* Copyright (c) 2025, The Tor Project, Inc.
   See LICENSE for licensing information. */
/**
 * \file  dp_mech.c
 * \brief Implements differential-privacy mechanisms
 *        and defines different algoritms.
 */

#include "dp_mech_updated.h"

#include "core/or/or.h"
#include "lib/crypt_ops/crypto_rand.h"
#include <math.h>
#include <stdbool.h>
#include <stdlib.h>

static bool randomized_response(bool true_value, double epsilon);
static int uniform_mechanism(int lower, int upper);
static int exponential_mechanism(double epsilon, int target, int lower,
                                 int upper);
static int laplace_mechanism(double epsilon, int target, int lower, int upper);
static int poisson_mechanism(double epsilon, int target, int lower, int upper);
static int normal_mechanism(double epsilon, int target, int lower, int upper);

static double uniform(void);
static double sample_laplace(double scale);
static double sample_normal(double epsilon);
static double sample_poisson(double lambda);

const double DEFAULT_SENSITIVITY =
    1.0; /** < Default sensitivity for DP mechanisms */
const double DEFAULT_DELTA =
    1e-5; /** < Default delta for DP mechanisms, used in Normal mechanism */

dp_mechanism_t
string_to_dp_mechanism_type(char *mechanism_str)
{
  if (!strcasecmp(mechanism_str, "UNIFORM")) {
    return DP_MECHANISM_UNIFORM;
  } else if (!strcasecmp(mechanism_str, "EXPONENTIAL")) {
    return DP_MECHANISM_EXPONENTIAL;
  } else if (!strcasecmp(mechanism_str, "POISSON")) {
    return DP_MECHANISM_POISSON;
  } else if (!strcasecmp(mechanism_str, "LAPLACE")) {
    return DP_MECHANISM_LAPLACE;
  } else if (!strcasecmp(mechanism_str, "NORMAL")) {
    return DP_MECHANISM_NORMAL;
  } else if (!strcasecmp(mechanism_str, "RANDOMIZED_RESPONSE")) {
    return DP_MECHANISM_RAND_RESPONSE;
  } else if (!strcasecmp(mechanism_str, "PARETO")) {
    return DP_MECHANISM_PARETO;
  } else if (!strcasecmp(mechanism_str, "BERNOULLI")) {
    return DP_MECHANISM_BERNOULLI;
  } else {
    log_warn(LD_BUG,
             "Unknown Differential Private Mechanism: %s!"
             "Only accept uniform, exponential & rand_response",
             mechanism_str);
    return DP_MECHANISM_UNKNOWN; // Default to uniform
  }
}

const char *
dp_mechanism_type_to_string(dp_mechanism_t mechanism)
{
  switch (mechanism) {
  case DP_MECHANISM_UNIFORM:
    return "UNIFORM";
  case DP_MECHANISM_EXPONENTIAL:
    return "EXPONENTIAL";
  case DP_MECHANISM_POISSON:
    return "POISSON";
  case DP_MECHANISM_LAPLACE:
    return "LAPLACE";
  case DP_MECHANISM_NORMAL:
    return "NORMAL";
  case DP_MECHANISM_RAND_RESPONSE:
    return "RANDOMIZED_RESPONSE";
  case DP_MECHANISM_PARETO:
    return "PARETO";
  case DP_MECHANISM_BERNOULLI:
    return "BERNOULLI";
  case DP_MECHANISM_UNKNOWN:
  default:
    log_warn(LD_BUG,
             "Unknown Differential Private Mechanism: %d!"
             "Only accept DP_MECHANISM_UNIFORM, DP_MECHANISM_EXPONENTIAL"
             ",DP_MECHANISM_RAND_RESPONSE, DP_MECHANISM_POISSON, DP_MECHANISM_LAPLACE, DP_MECHANISM_NORMAL, DP_MECHANISM_PARETO & DP_MECHANISM_BERNOULLI",
             mechanism);
    return "UNKNOWN"; // Should not happen
  }
}
/**
 * @brief Generates a differentially private boolean value
 *
 * @param epsilon Epsilon value for differential privacy.
 * @return true is the standard boolean. Always returns true if
 * epsilon is 0.0.
 */
bool
dp_generate_bool(bool true_value, double epsilon)
{
  return randomized_response(true_value, epsilon);
}

int
dp_generate_int(int min, int max, int target, double epsilon,
                dp_mechanism_t mechanism)
{
  if (min > max) {
    log_warn(LD_BUG, "Invalid range: min (%d) > max (%d)", min, max);
    return target; // This should not happen, but return target to avoid crash.
  }

  if (randomized_response(true, epsilon)) {
    return target; // Return target with.
  }

  switch (mechanism) {
  case DP_MECHANISM_EXPONENTIAL:
    return exponential_mechanism(epsilon, target, min, max);
  case DP_MECHANISM_POISSON:
    return poisson_mechanism(epsilon, target, min, max);
  case DP_MECHANISM_LAPLACE:
    return laplace_mechanism(epsilon, target, min, max);
  case DP_MECHANISM_NORMAL:
    return normal_mechanism(epsilon, target, min, max);
  case DP_MECHANISM_UNIFORM:
  case DP_MECHANISM_RAND_RESPONSE: // Will fall through to uniform
    return uniform_mechanism(min, max);
  case DP_MECHANISM_PARETO:
    return pareto_mechanism(epsilon, target, min, max);
  case DP_MECHANISM_BERNOULLI:
    return bernoulli_mechanism(epsilon, target, min, max);
  case DP_MECHANISM_UNKNOWN:
  default:
    log_warn(LD_BUG,
             "Unknown Differential Private Mechanism: %d!"
             "Only accept DP_MECHANISM_EXPONENTIAL, DP_MECHANISM_RAND_RESPONSE, "
             "DP_MECHANISM_PARETO, DP_MECHANISM_BERNOULLI & DP_MECHANISM_UNIFORM",
             mechanism);
    return target;
  }
}

/******************************************************************
 * Distribution Mechanisms
 ******************************************************************/
static int
bernoulli_mechanism(double epsilon, int target, int lower, int upper){
  if (epsilon < 0.0) {
    return target; 
  }

  double p = exp(epsilon) / (exp(epsilon) + 1.0);

  if (uniform() < p) {
    return target;  
  }

  int noise = (uniform() < 0.5) ? -1 : 1;
  int result = target + noise;

  return CLAMP(lower, result, upper);
}

static int
pareto_mechanism(double epsilon, int target, int lower, int upper){
  if (epsilon <= 0.0) {
    return target;
  }

  double alpha = epsilon;
  double xm = 1.0;

  double u = uniform();
  double pareto_sample = xm / pow(u, 1.0 / alpha);

  if (uniform() < 0.5) {
    pareto_sample = -pareto_sample;
  }

  int result = target + (int)round(pareto_sample);

  return CLAMP(lower, result, upper);
}

static bool
randomized_response(bool true_value, double epsilon)
{
  if (epsilon < 0.0) {
    return true_value; // no noise, no privacy
  }
  double p = exp(epsilon) / (exp(epsilon) + 1.0);

  if (uniform() < p) {
    return true_value;
  }
  return !true_value; // flip the value
}

static int
uniform_mechanism(int lower, int upper)
{
  int range = upper - lower;
  return lower + (int)(uniform() * range);
}

static int
exponential_mechanism(double epsilon, int target, int lower, int upper)
{
  int range = upper - lower + 1;
  double *scores = tor_malloc(range * sizeof(double));
  double *weights = tor_malloc(range * sizeof(double));
  double max_score = -INFINITY, sum = 0.0;

  for (int i = 0; i < range; ++i) {
    int val = lower + i;
    scores[i] = -fabs((double)val - target);
    if (scores[i] > max_score)
      max_score = scores[i];
  }
  for (int i = 0; i < range; ++i) {
    weights[i] =
        exp((epsilon * (scores[i] - max_score)) / (2 * DEFAULT_SENSITIVITY));
    sum += weights[i];
  }
  double r = uniform() * sum, cum = 0.0;
  for (int i = 0; i < range; ++i) {
    cum += weights[i];
    if (r <= cum) {
      tor_free(scores);
      tor_free(weights);
      return lower + i;
    }
  }
  tor_free(scores);
  tor_free(weights);
  return upper;
}

static int
laplace_mechanism(double epsilon, int target, int lower, int upper)
{
  const double scale = (target - lower) / (epsilon * 2.0);
  double result = round(target + sample_laplace(scale));

  return CLAMP(lower, (int)result, upper);
}

static int
poisson_mechanism(double epsilon, int target, int lower, int upper)
{
  const double lambda = (double)(upper - lower) / epsilon;
  double result = target + sample_poisson(lambda);
  return CLAMP(lower, (int)result, upper);
}

static int
normal_mechanism(double epsilon, int target, int lower, int upper)
{
  double noisy;
  do {
    noisy = target + round(sample_normal(epsilon));
  } while (noisy < lower || noisy > upper);

  return (int)noisy;
}

/******************************************************************
 * Helper Functions
 ******************************************************************/

static double
uniform(void)
{
  return crypto_fast_rng_get_uint(get_thread_fast_rng(), 100) / 100.0;
}

static double
sample_laplace(double scale)
{
  double u = uniform();
  if (u < 0.5) {
    return scale * log(2 * u);
  } else {
    return -scale * log(2 * (1 - u));
  }
}

static double
sample_normal(double epsilon)
{
  double sigma =
      sqrt(2 * log(1.25 / DEFAULT_DELTA)) * DEFAULT_SENSITIVITY / epsilon;
  double u1 = uniform(), u2 = uniform();
  return sigma * sqrt(-2 * log(u1)) * cos(2 * M_PI * u2);
}

static double
sample_poisson(double lambda)
{
  double p = exp(-lambda);
  double sum = p;
  int k = 0;

  while (sum < uniform()) {
    k++;
    p *= lambda / k;
    sum += p;
  }

  return k;
}
