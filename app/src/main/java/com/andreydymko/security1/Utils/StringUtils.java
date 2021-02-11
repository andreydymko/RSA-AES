package com.andreydymko.security1.Utils;

import java.util.Arrays;

public class StringUtils {

    public static String getFilledStr(int length, char charToFill) {
        if (length > 0) {
            char[] array = new char[length];
            Arrays.fill(array, charToFill);
            return new String(array);
        }
        return "";
    }

    public static String portionString(final String string,
                                       final int offset,
                                       final int nLength) {
        return string.substring(
                offset,
                offset + Math.min(string.length() - offset, nLength)
        );
    }
}
