package com.andreydymko.security1.AES;

import java.text.MessageFormat;
import java.util.Arrays;

public class AES {
    private int keyLen, Nb, Nk, Nr, rowCnt, blockSize;
    private AESHelper aesHelper;

    public AES(int keyLength) {
        switch (keyLength) {
            case 128:
                this.Nk = 4;
                this.Nr = 10;
                break;
            case 192:
                this.Nk = 6;
                this.Nr = 12;
                break;
            case 256:
                this.Nk = 8;
                this.Nr = 14;
                break;
            default:
                throw new IllegalArgumentException("Key length should be 128, 192 or 256");
        }
        this.keyLen = keyLength;
        this.Nb = 4;
        this.rowCnt = 4;
        this.blockSize = this.rowCnt * this.Nb;
        this.aesHelper = new AESHelper(Nb, Nk, Nr, rowCnt);
    }

    public byte[] encrypt(final byte[] input, final byte[] key) {
        if (key.length * Byte.SIZE > keyLen) {
            throw new IllegalArgumentException(MessageFormat.format("Key length should be less than {0} bits", keyLen));
        }

        int[][] keySchedule = aesHelper.keyExpansion(key);

        byte[] result = new byte[(int) (Math.ceil( (double) input.length / (blockSize)) * blockSize)];
        byte[] tempOut = new byte[blockSize];

        int remainedBytes = input.length % blockSize;
        for (int i = 0, end = input.length - remainedBytes; i < end; i += blockSize) {
            encryptBytes(input, i, keySchedule, tempOut);
            System.arraycopy(tempOut, 0, result, i, blockSize);
        }
        if (remainedBytes > 0) {
            byte[] tempIn = new byte[blockSize];
            System.arraycopy(input, input.length - remainedBytes, tempIn, 0, remainedBytes);
            Arrays.fill(tempIn, remainedBytes, tempIn.length - 1, (byte) 0x00);
            tempIn[tempIn.length - 1] = 0x01;
            encryptBytes(tempIn, 0, keySchedule, tempOut);
            System.arraycopy(tempOut, 0, result, result.length - blockSize, blockSize);
        }

        return result;
    }

    public void encryptBytes(final byte[] input, int startPos, final int[][] keySchedule, byte[] output) {
        if (output.length < blockSize) {
            throw new IllegalArgumentException(MessageFormat.format("Output array should be at least {0} elements long, currently = {1}", blockSize, output.length));
        }

        int[][] state = new int[rowCnt][Nb];
        for (int i = 0; i < rowCnt; i++) {
            for (int j = 0; j < Nb; j++) {
                state[i][j] = input[startPos + rowCnt * j + i] & 0xFF;
            }
        }

        aesHelper.addRoundKey(state, keySchedule, 0);

        for (int i = 1; i < Nr; i++) {
            aesHelper.subBytes(state, false);
            aesHelper.shiftRows(state, false);
            aesHelper.mixColumns(state, false);
            aesHelper.addRoundKey(state, keySchedule, i);
        }

        aesHelper.subBytes(state, false);
        aesHelper.shiftRows(state, false);
        aesHelper.addRoundKey(state, keySchedule, Nr);

        for (int i = 0; i < rowCnt; i++) {
            for (int j = 0; j < Nb; j++) {
                output[i + rowCnt * j] = (byte) state[i][j];
            }
        }
    }

    public byte[] decrypt(final byte[] input, final byte[] key) {
        if (input.length % blockSize != 0) {
            throw new IllegalArgumentException(MessageFormat.format("Input array length is not compatible with AES, should be multiple of {0}", blockSize));
        }
        if (key.length * Byte.SIZE > keyLen) {
            throw new IllegalArgumentException(MessageFormat.format("Key length should be less than {0} bits", keyLen));
        }

        int[][] keySchedule = aesHelper.keyExpansion(key);

        // decrypt last block, to see if there are fillers
        byte[] tempOut = new byte[blockSize];
        decryptBytes(input, input.length - blockSize, keySchedule, tempOut);
        int bytesFillersCount = 0;
        if (tempOut[tempOut.length - 1] == 0x01) {
            bytesFillersCount++;
            for (int i = tempOut.length - 2; i > 0; i--) {
                if (tempOut[i] == 0x00) {
                    bytesFillersCount++;
                } else {
                    break;
                }
            }
        }

        int lastBlockLen = blockSize - bytesFillersCount;
        byte[] result = new byte[input.length - bytesFillersCount];
        System.arraycopy(tempOut, 0, result, result.length - lastBlockLen, lastBlockLen);

        for (int i = 0; i < result.length - lastBlockLen; i += blockSize) {
            decryptBytes(input, i, keySchedule, tempOut);
            System.arraycopy(tempOut, 0, result, i, blockSize);
        }

        return result;
    }

    public void decryptBytes(final byte[] input, int startPos, final int[][] keySchedule, byte[] output) {
        if (output.length < blockSize) {
            throw new IllegalArgumentException(MessageFormat.format("Output array should be at least {0} elements long, currently = {1}", blockSize, output.length));
        }

        int[][] state = new int[rowCnt][Nb];
        for (int i = 0; i < rowCnt; i++) {
            for (int j = 0; j < Nb; j++) {
                state[i][j] = input[startPos + rowCnt * j + i] & 0xFF;
            }
        }

        aesHelper.addRoundKey(state, keySchedule, Nr);

        for (int i = Nr - 1; i > 0 ; i--) {
            aesHelper.shiftRows(state, true);
            aesHelper.subBytes(state, true);
            aesHelper.addRoundKey(state, keySchedule, i);
            aesHelper.mixColumns(state, true);
        }

        aesHelper.shiftRows(state, true);
        aesHelper.subBytes(state, true);
        aesHelper.addRoundKey(state, keySchedule, 0);

        for (int i = 0; i < rowCnt; i++) {
            for (int j = 0; j < Nb; j++) {
                output[i + rowCnt * j] = (byte) state[i][j];
            }
        }
    }
}
