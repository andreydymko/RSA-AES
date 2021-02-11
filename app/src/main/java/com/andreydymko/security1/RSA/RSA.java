package com.andreydymko.security1.RSA;

import com.andreydymko.security1.Utils.MathUtils;
import com.andreydymko.security1.Utils.StringUtils;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

public class RSA {

    public static KeySet generateKeySet(int digitsCount, Random random) {
        int pLength, qLength;
        BigInteger P, Q, N;
        do {
            pLength = ThreadLocalRandom.current().nextInt(digitsCount / 4, digitsCount - digitsCount / 4);
            qLength = digitsCount - pLength;
            P = MathUtils.generatePrime(pLength, random);
            Q = MathUtils.generatePrime(qLength, random);

            N = P.multiply(Q);
        } while (P.compareTo(Q) == 0 || N.toString().length() != digitsCount);

        BigInteger d = MathUtils.eulerFunction(P, Q);
        BigInteger S = MathUtils.findLesserCoPrime(d, random); // S < d, and also S should co-prime with d, random // public key
        BigInteger e = S.modInverse(d); // e * S mod d = 1 // euclid extended algorithm // private key

        return new KeySet(S, e, N);
    }

    public static byte[] encryptData(final byte[] input, final BigInteger key, final BigInteger N) {
        int nLength = N.toString().length() - 1;
        String numbersStr = RSAHelper.bytesToNumbers(input);
        StringBuilder builder = new StringBuilder(numbersStr.length() + nLength);
        for (int i = 0; i < numbersStr.length(); i += nLength) {
            builder.append(
                    String.format(Locale.US,"%0" + (nLength + 1) + "d",
                            new BigInteger(StringUtils.portionString(numbersStr, i, nLength)).modPow(key, N))
            );
        }
        return new RSAEncrypted(numbersStr.length(), builder.toString().getBytes(StandardCharsets.ISO_8859_1)).toByteArray();
    }

    public static byte[] decryptData(byte[] input, final BigInteger key, final BigInteger N) {
        RSAEncrypted encrypted = RSAEncrypted.fromByteArray(input);
        int nLength = N.toString().length();
        String numbers = new String(encrypted.getData(), StandardCharsets.ISO_8859_1);
        StringBuilder builder = new StringBuilder(numbers.length());
        int origLastBlockLen = (encrypted.getLength() % (nLength - 1));
        int forEnd = numbers.length() - nLength;
        for (int i = 0; i < forEnd; i += nLength) {
            builder.append(
                    String.format(Locale.US,"%0" + (nLength - 1) + "d",
                            new BigInteger(StringUtils.portionString(numbers, i, nLength)).modPow(key, N))
            );
        }
        builder.append(
                String.format(Locale.US,"%0" + origLastBlockLen + "d",
                        new BigInteger(StringUtils.portionString(numbers, forEnd, nLength)).modPow(key, N))
        );

        return RSAHelper.numbersToBytes(builder.toString());
    }

    public static class KeySet {
        private BigInteger publicKey, privateKey, N;

        public KeySet(BigInteger publicKey, BigInteger privateKey, BigInteger N) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
            this.N = N;
        }

        public BigInteger getPublicKey() {
            return publicKey;
        }

        public BigInteger getPrivateKey() {
            return privateKey;
        }

        public BigInteger getN() {
            return N;
        }
    }

    private static class RSAEncrypted {
        private int length;
        private byte[] data;


        public RSAEncrypted(int length, byte[] data) {
            this.length = length;
            this.data = data;
        }

        public int getLength() {
            return length;
        }

        public byte[] getData() {
            return data;
        }

        public byte[] toByteArray() {
            int intBytes = Integer.SIZE/Byte.SIZE;
            byte[] res = new byte[intBytes + data.length];
            ByteBuffer byteBuffer = ByteBuffer.allocate(intBytes).putInt(length);
            byteBuffer.rewind();
            byteBuffer.get(res, 0, intBytes);
            System.arraycopy(data, 0, res, intBytes, data.length);
            return res;
        }

        public static RSAEncrypted fromByteArray(byte[] bytes) {
            int intBytes = Integer.SIZE/Byte.SIZE;
            ByteBuffer byteBuffer = ByteBuffer.allocate(intBytes).put(bytes, 0, intBytes);
            byteBuffer.rewind();
            return new RSAEncrypted(byteBuffer.getInt(), Arrays.copyOfRange(bytes, intBytes, bytes.length));
        }
    }
}
