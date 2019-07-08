/*
 *Date: 2019/06/28
 *Project: Proof Of Concept for: There are 10 Types of Vectors (and Polynomials)
 *File:utils.hpp
 *  Contains function declations of utility functions used in this project.
 */

#ifndef __horners_hpp__
#define __horners_hpp__
#include<gmpxx.h>
#include<NTL/ZZ_p.h>
#include<NTL/ZZ_pX.h>
extern"C"{
    #include<relic/relic_core.h>
}

#include"pedersen.hpp"
#include<vector>
using namespace NTL;
using namespace std;
/* Function: horners_method
 * 
 * Computes the evaluation of a polynomial with coefficients as commitments, done using horners method for evaluation of polynomials.
 *
 * vector<Pedersen_Commitments>: coefficients of the polynomial
 * size_t: number of coefficients 
 * bn_t: value to evaluate the polynomail at.
 * 
 * Returns: Pedersen_Commitment to the evaluation.
 */
Pedersen_Commitment horners_method(vector<Pedersen_Commitment>,size_t,bn_t);

/* Function: horners_method
 *
 * Computes the evaluation of a polynomial with coefficients in Zp, done using NTL's polynomial evaluation.
 * 
 * vector<ZZ_p>: coefficients of the polynomial
 * ZZ_p: Value ot evaluate the polynomial at.
 * 
 * Return: ZZ_p, the evaluation of the polynomail at set value.
 */
ZZ_p horners_method(vector<ZZ_p>,ZZ_p);

/*Function: multi_exp
 *
 * Computes the value defined by commitments[1]^exponents[1]*...*commitment[n]^exponents[n].
 * 
 * Pedersen P: Used to create Pedersen_Commitments.
 * vector<Pederesen_Commitment> commitments: The vector of commitments to be raised to exponents,
 * vector<ZZ_p> exponents: The vector of ZZ_p used to raise the commitment to.
 * const uint window_size: The the size of the preoccupation step reasonable values are between [1-8]
 * 
 * Returns: Result of the computation.
 */
Pedersen_Commitment multi_exp(Pedersen& P,vector<Pedersen_Commitment> commitments,vector<ZZ_p> exponents, const uint window_size);

/*Function: multi_exp_sub -- multi-exponentiation-subcomputation
 *
 * Call multi_exp on subsets of the larges computation; this should be used if ram is exceeded.
 * 
 * const int chunks: number of descrete disjoint subsets to call multiexp on. 
 * 
 * Returns: result
 */
Pedersen_Commitment multi_exp_sub(Pedersen& P, vector<Pedersen_Commitment> commitments, vector<ZZ_p> exponents,const int window_size, const int chucks);

/*Function: conv
 * 
 * Converts between NTL and RELIC-Toolkit
 * 
 * bn_t out: Relic big integer
 * ZZ_p in: NTL big integer subject to prime p
 */
void conv(bn_t out, ZZ_p in);

/*Function: conv
 * 
 * Converts between NTL and RELIC-Toolkit
 * 
 * bn_t in: Relic big integer
 * ZZ_p out: NTL big integer subject to prime p
 */
void conv(ZZ_p& out, bn_t in);

/*Function: conv
 * 
 * Converts between NTL and RELIC-Toolkit
 * 
 * bn_t in: Relic big integer
 * ZZ out: NTL big integer
 */
void conv(ZZ& out,bn_t in);

/* Function: genRandomT
 *
 * Creates a random value subject to the defined security parameters.
 * 
 * uint lambda: desired security such that soundness is 2^{-lambda}
 * uint bitlength: bitlength=lg(N) such that N is the length of the vector in the ZKP
 * 
 * Returns: random value.
 */
ZZ_p genRandomT(uint lambda, uint bitlength);

/* Function: genRandom
 *
 * Creates random value subject ot defined security parameter
 * 
 * unint lambda: desired security such that soundness is 2^{-lambda}
 * 
 * Returns: random value.
 */
ZZ_p genRandom(uint lambda);
#endif