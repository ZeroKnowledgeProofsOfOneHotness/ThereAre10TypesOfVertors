/*
 *Date: 2019/06/28
 *Project: Proof Of Concept for: There are 10 Types of Vectors (and Polynomials)
 *File: pedersen.hpp
 *  Contains Class and method declarations of data structures needed for petersen commitments
 */
 
#ifndef __pedersen_hpp_
#define __pedersen_hpp_
extern"C"{
    #include<relic/relic_core.h>
}
#include<iostream>
#include<NTL/ZZ_p.h>
#include"utils.hpp"
using namespace NTL;
using namespace std;
/* Class: Pedersen_Commitment
 *
 * Responsible for the encapsulation of data members required for a pedersen Commitment, also wrapping relic's elliptic curve functions.
 */
class Pedersen_Commitment
{
    private:
        bn_t message; //Interger that is commited to.
        bn_t randomKey; //Interger that provides the binding and hinding properties
        ep_t commitment; //Elliptic curve point such that commitment = message*g+randomKey*h
        bn_t p; //Prime integer of the degree of the elliptic curve.
    public:
        /* Operator +
         *
         * Provides an addition operator between Pedersen_Commitments
         *
         * Pedersen_Commitment other: The other operand in this binary operation.
         * 
         * Returns: this+other
         */
        Pedersen_Commitment operator+(const Pedersen_Commitment& other);
        /* Operator +
         *
         * Provides an field multiplication operator between Pedersen_Commitments and integers
         *
         * bn_t other: the integer used in the feild operation.
         * 
         * Returns: this*other.
         * 
         * NOTE: this requires the opperations to be Pedersen_Commitment*bn_t
         */
        Pedersen_Commitment operator*(const bn_t other);
        /* Operator -
         *
         * Provides an additive inverse operator between Pedersen_Commitments
         *
         * Pedersen_Commitment right: The value that will be inverted, then added to this
         * 
         * Returns: this+(-right)
         */
        Pedersen_Commitment operator-(const Pedersen_Commitment& right);
        /* Operator ==
         * 
         * Provides a method for checking equality between commitments. were equality is defied as the same elliptical curve point.
         * 
         * Pedersen_Commitemnt other: The commitment that will be checking equality against this.
         * 
         * returns true if and only if other==this
         */
        bool operator==(const Pedersen_Commitment& other);
        /* Method: Constructor
         * 
         *  Default Constructor: Zero's all the data and creates object.
         */
        Pedersen_Commitment();
        /* Method: Constructor
         * 
         * Creates the commitment object.
         * 
         * bn_t: the message 
         * bn_t: the random key
         * ep_t: elliptic curve point
         * 
         * NOTE: one would hope never to call this function let Pedersen create all the objects such that they are well formed.
         */
        Pedersen_Commitment(bn_t,bn_t,ep_t);
        /* Method: get_message
         * 
         * the  getter for the message attribute
         * 
         * bn_t out: copied out value of message.
         */
        void get_message(bn_t);
        /* Method: get_randomKey
         *
         * the getter for the randomKey attribute
         * 
         * bn_t out: copied out value of the random key.
         */
        void get_randomKey(bn_t);
        /* Method: get_commitment
         *
         * The getter for the commitment attribute
         * 
         * ep_t out: coppied out value of the commitment
         */
        void get_commitment(ep_t);
        /* Method: print
         *
         * Prints out the ellipical curve point along with it's witnesses.
         */
        void print();
        /* Method: Deconstructor
         * Destroys things this object owns
         */
        ~Pedersen_Commitment();

};

/* Class: Pedersen
 *
 * The class used to create petersen commitments, holds to context of the generators of the ellipical curve group g and h, such that every commitment commited with the same g and h.
 * 
 * NOTE: only one instance should be used in this code.
 */
class Pedersen
{
    private:
        ep_t g,h;//The generators
    public:
        /* Method: Constructor
         * 
         * Chooses the g and h that is used for creation of pedersen commitments.
         */
        Pedersen();
        /* Method: Deconstructor
         * 
         * Frees any memory that this object owns.
         */
        ~Pedersen();
        /* Method: commit
         * 
         * Creates a Pederesen_Commitment, subject to g and h
         * 
         * bn_t a: the integer used as exponent of g
         * bn_t b: the integer used as exponent of h
         * 
         * Returns Petersen_Commitment(a*g+b*h,a,b)
         */
        Pedersen_Commitment commit(bn_t,bn_t);
        /* Method: commit
         *
         * Calls commit but converst to bn_t first,
         * 
         * returns commit();
         */
        Pedersen_Commitment commit(ZZ_p,ZZ_p);

};
#endif