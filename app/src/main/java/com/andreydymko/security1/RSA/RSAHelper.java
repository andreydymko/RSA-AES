package com.andreydymko.security1.RSA;

import com.andreydymko.security1.Utils.MathUtils;
import com.andreydymko.security1.Utils.StringUtils;


public class RSAHelper {
    private final static int longDecimals = 19;
    private final static int longBytes = Long.SIZE/Byte.SIZE;
    private final static int intDecimals = 10;
    private final static int intBytes = Integer.SIZE/Byte.SIZE;
    private final static int byteDecimals = 3;
    private final static int byteBytes = 1;

    public static String bytesToNumbers(final byte[] input) {
        StringBuilder stringBuilder = new StringBuilder((int) (input.length/Math.round(MathUtils.Log(10, 2))));
        String strToAdd;
        for (byte byt : input) {
            strToAdd = Integer.toString(byt & 0xFF);
            stringBuilder.append(StringUtils.getFilledStr(byteDecimals - strToAdd.length(), '0')).append(strToAdd);
        }
        return stringBuilder.toString();
    }

    public static byte[] numbersToBytes(final String input) {
        byte[] res = new byte[input.length()/byteDecimals];
        for (int i = 0, j = 0; i < input.length(); i += byteDecimals, j++) {
            res[j] = (byte) (Integer.parseInt(StringUtils.portionString(input, i, byteDecimals), 10) | 0xFFFFFF00);
        }
        return res;
    }
}
