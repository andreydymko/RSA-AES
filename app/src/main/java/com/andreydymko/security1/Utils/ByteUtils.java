package com.andreydymko.security1.Utils;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Collection;

public class ByteUtils {
    private final static int longBytes = Long.SIZE/Byte.SIZE;
    private final static int intBytes = Integer.SIZE/Byte.SIZE;

    @Deprecated
    public static byte[] longToBytes(long l) {
        byte[] result = new byte[longBytes];
        for (int i = longBytes - 1; i >= 0; i--) {
            result[i] = (byte)(l & 0xFF);
            l >>= longBytes;
        }
        return result;
    }

    @Deprecated
    public static long bytesToLong(final byte[] bytes, int offset) {
        int bytesToUse = Math.min(bytes.length - offset, longBytes);
        long result = 0;
        for (int i = offset; i < bytesToUse + offset; i++) {
            result <<= longBytes;
            result |= (bytes[i] & 0xFF);
        }
        return result;
    }

    @Deprecated
    public static byte[] intToBytes(int integer) {
        byte[] result = new byte[intBytes];
        for (int i = intBytes - 1; i >= 0; i--) {
            result[i] = (byte)(integer & 0xFF);
            integer >>= intBytes;
        }
        return result;
    }

    public static int bytesToInt(final byte[] bytes, ByteOrder byteOrder) {
        ByteBuffer byteBuffer = ByteBuffer.allocate(intBytes).order(byteOrder);
        for (int i = 0; i < intBytes - bytes.length; i++) {
            byteBuffer.put((byte) 0);
        }
        for (int i = 0; i < bytes.length; i++) {
            byteBuffer.put(bytes[i]);
        }
        byteBuffer.rewind();
        return byteBuffer.getInt();
    }

    @Deprecated
    public static int bytesToInt(final byte[] bytes, int offset) {
        int bytesToUse = Math.min(bytes.length - offset, intBytes);
        int result = 0;
        for (int i = offset; i < bytesToUse + offset; i++) {
            result <<= intBytes;
            result |= (bytes[i] & 0xFF);
        }
        return result;
    }


    public static byte[] mergeArrays(Collection<byte[]> collection) {
        int totalLength = 0;
        for (byte[] bytes : collection) {
            totalLength += bytes.length;
        }
        byte[] mergedData = new byte[totalLength];
        int currPosition = 0;
        for (byte[] bytes : collection) {
            System.arraycopy(bytes, 0, mergedData, currPosition, bytes.length);
            currPosition += bytes.length;
        }
        return mergedData;
    }

    public static byte[] collectionToArray(Collection<Byte> collection) {
        byte[] res = new byte[collection.size()];
        int i = 0;
        for (byte b : collection) {
            res[i] = b;
            i++;
        }
        return res;
    }
}
