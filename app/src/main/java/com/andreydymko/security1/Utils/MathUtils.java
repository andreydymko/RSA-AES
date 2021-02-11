package com.andreydymko.security1.Utils;

import java.math.BigInteger;
import java.util.Random;

public class MathUtils {
    public static double Log(double number, double base) {
        return Math.log(number) / Math.log(base);
    }

    public static BigInteger generatePrime(int numOfDigits, Random random) {
        double bitsPerDigitApprox = numOfDigits <= 18 ? //18 == String.valueOf(Long.MAX_VALUE).length() - 1
                (Math.floor(MathUtils.Log(Math.pow(10, numOfDigits)*5, 2)) + 1)
                        / (Math.floor(MathUtils.Log(Math.pow(10, numOfDigits)*5, 10)) + 1) :
                MathUtils.Log(10, 2);
        return BigInteger.probablePrime((int) Math.round(numOfDigits * bitsPerDigitApprox), random);
    }

    public static BigInteger eulerFunction(final BigInteger P, final BigInteger Q) {
        // (P - 1)*(Q - 1)
        return (P.subtract(BigInteger.ONE)).multiply(Q.subtract(BigInteger.ONE));
    }

    public static BigInteger findLesserCoPrime(BigInteger with, Random random) {
        int length = with.bitLength() - 1;
        BigInteger coPrime = BigInteger.probablePrime(length, random);
        while (!with.gcd(coPrime).equals(BigInteger.ONE) ) {
            coPrime = BigInteger.probablePrime(length, random);
        }
        return coPrime;
    }
}
