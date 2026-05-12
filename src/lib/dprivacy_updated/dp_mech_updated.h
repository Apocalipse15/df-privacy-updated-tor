/* Copyright (c) 2025, The Tor Project, Inc.
   See LICENSE for licensing information. */
/**
 * \file dp_mech.h
 * \brief Header for dp_mech.c
 */

#ifndef TOR_DP_H
#define TOR_DP_H

#include <stdbool.h>

typedef enum {
  DP_MECHANISM_NORMAL, /** < Normal mechanism */
  DP_MECHANISM_UNIFORM, /** < Uniform mechanism */
  DP_MECHANISM_POISSON, /** < Poisson mechanism */
  DP_MECHANISM_LAPLACE, /** < Laplace mechanism */
  DP_MECHANISM_EXPONENTIAL, /** < Exponential mechanism */
  DP_MECHANISM_RAND_RESPONSE, /** < Randomized response mechanism */
  DP_MECHANISM_PARETO, /** < Pareto mechanism */
  DP_MECHANISM_BERNOULLI, /** < Bernoulli mechanism */
  DP_HYBRID_MECHANISM, /** < Hybrid mechanism */
  DP_MECHANISM_HYBRID_PROB, /** < Hybrid mechanism with probabilities */
  DP_MECHANISM_UNKNOWN
} dp_mechanism_t;

extern const double DEFAULT_SENSITIVITY;
extern const double DEFAULT_DELTA;

/** Generates a differentially private integer within [min, max] */
int dp_generate_int(int min, int max, int target, double epsilon,
                    dp_mechanism_t mechanism);

/** Generates a differentially private boolean value */
bool dp_generate_bool(bool true_value, double epsilon);

/** Parses a string into a dp_mechanism_t */
dp_mechanism_t string_to_dp_mechanism_type(char *mechanism_str);

/** Returns the equivalent string of the dp_mechanism_t */
const char *dp_mechanism_type_to_string(dp_mechanism_t mechanism);

#endif /* TOR_DP_H */
