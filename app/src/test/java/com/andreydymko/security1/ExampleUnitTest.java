package com.andreydymko.security1;

import com.andreydymko.security1.RSA.RSA;
import com.andreydymko.security1.RSA.RSAHelper;
import com.andreydymko.security1.Utils.ByteUtils;
import com.andreydymko.security1.Utils.MathUtils;

import org.junit.Test;

import java.lang.reflect.Array;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.Locale;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

import static org.junit.Assert.*;

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
public class ExampleUnitTest {
    @Test
    public void addition_isCorrect() {
        assertEquals(4, 2 + 2);
    }

    @Test
    public void testPrime() {
        ArrayList<Integer> list = new ArrayList<>();
        int digitsCount = 44;
        Random random = new Random();
        for (int i = 0; i < 10000; i++) {
            int pLength = ThreadLocalRandom.current().nextInt(digitsCount/4, digitsCount - digitsCount/4);
            int qLength = digitsCount - pLength;
            BigInteger P = MathUtils.generatePrime(pLength, random);
            BigInteger Q = MathUtils.generatePrime(qLength, random);
            list.add(P.multiply(Q).toString().length());
        }

        assertEquals((int) Collections.max(list), digitsCount);
        assertEquals((int) Collections.min(list), digitsCount);
    }

    @Test
    public void testByteToInt() {
        byte[] input = new byte[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01};
        int sizeOfLong = 8;
        StringBuilder stringBuilder = new StringBuilder(input.length/sizeOfLong);
        ByteBuffer byteBuffer = ByteBuffer.wrap(input);

        while (byteBuffer.hasRemaining()) {
            System.out.println(byteBuffer.remaining());
            if (byteBuffer.remaining() >= sizeOfLong) {
                stringBuilder.append(byteBuffer.getLong());
            } else {
                System.out.println("fef");
                byte[] remainingBytes = new byte[byteBuffer.remaining()];
                byteBuffer.get(remainingBytes, 0, remainingBytes.length);
                //System.out.println(Arrays.toString(remainingBytes));
                long res = 0;
                for (int i = remainingBytes.length - 1; i >= 0; i--) {
                    res <<= Integer.BYTES;
                    res |= (remainingBytes[i] & 0xFF);
                    System.out.println(res);
                }
                stringBuilder.append(res);
            }
            System.out.println(stringBuilder.toString());
        }
        assertEquals(4, 2 + 2);
    }

    @Test
    public void testByte() {
        System.out.println(ByteUtils.bytesToLong(new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01}, 2));
        assertEquals(4, 2 + 2);
    }

    @Test
    public void testFor() {
        for (int i = 0; i < 8; i += 3) {
            System.out.println(i);
        }
    }

    @Test
    public void testMerge() {
        ArrayList<byte[]> arrayList = new ArrayList<>();
        arrayList.add(new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01});
        arrayList.add(new byte[]{0x00, 0x01, 0x01, 0x01});
        arrayList.add(new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00});
        byte[] res = ByteUtils.mergeArrays(arrayList);
        System.out.println(Arrays.toString(res));
        assertArrayEquals(
                new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x01,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00},
                res);
    }

    @Test
    public void testEncryption() {
        int nLength = 44;
        RSA.KeySet keySet = RSA.generateKeySet(nLength, new SecureRandom());
        System.out.println("public1 key:" + keySet.getPublicKey().toString());
        System.out.println("private key:" + keySet.getPrivateKey().toString());
        System.out.println("N111111 key:" + keySet.getN().toString());

        String testStr = "Я нашел тот самый момент, из-за которого возникала невозможность корректно дешифровать некоторые блоки.\n" +
                "\n" +
                "Если взять N и шифруемый блок, который в последствии \"испортится\" - назовем его Bloc:\n" +
                "Nkey = 29831577442118183758262720046018854350125493\n" +
                "Bloc = 90040790040320000580040480040580040480040790\n" +
                "\n" +
                "То мы заметим, что:\n" +
                "Bloc > N\n" +
                "(Кол-во разрядов одинаковое, но Bloc начинается с \"9\", в то время как N с \"2\")\n" +
                "Собственно это и не позволяет получить корректные данные из блока, т.к. преобразование становится необратимым даже при наличии ключа.\n" +
                "\n" +
                "В методичке, конечно, указано, что число заложенное в блок (которое мы возводим в большую степень) должно быть меньше N: \"разбивает его на блоки m1, m2,..., mi, где mi < N\" (страница 7, \"Процесс шифрования и дешифрования\"). Но думаю этот момент стоит осветить на следующей практике или лекции, или хоть где-нибудь, т.к. в Вашей видео-лекции этот момент упущен, да и в методичке этому очень важному условию уделено считай 4 символа.";

        byte[] encrypted = RSA.encryptData(testStr.getBytes(StandardCharsets.UTF_8), keySet.getPublicKey(), keySet.getN());
        byte[] arr1 = RSA.decryptData(encrypted, keySet.getPrivateKey(), keySet.getN());
        String decryptedStr = new String(arr1, StandardCharsets.UTF_8);
        System.out.println(decryptedStr);
        assertEquals(testStr, decryptedStr);
    }

    @Test
    public void bigIntCalc() {
        BigInteger orig = new BigInteger("90040790040320000580040480040580040480040790");
        BigInteger decoded = new BigInteger("00546057713965449305252319902523477429664311");

        BigInteger publicKey = new BigInteger("11446747168731689833003705540911791201609869");
        BigInteger privateKey = new BigInteger("7584606786099887971499416174799011351142725");

        BigInteger Nkey = new BigInteger("29831577442118183758262720046018854350125493");

        //System.out.println(orig.modPow(publicKey, Nkey));
        System.out.println(orig.modPow(publicKey, Nkey).modPow(privateKey, Nkey));
    }

    @Test
    public void testRSAHelper() {
        Random random = new Random();
        byte[] firstArr = new byte[8192];
        random.nextBytes(firstArr);

        String nums = RSAHelper.bytesToNumbers(firstArr);
        byte[] resArr = RSAHelper.numbersToBytes(nums);

        assertArrayEquals(firstArr, resArr);
    }

    @Test
    public void testUnsByte() {
        byte b = -123;
        System.out.println(Byte.toString(b));
        System.out.println(Integer.toString(b & 0xFF));
        System.out.println((byte) 133 | 0xFFFFFF00);
    }

    @Test
    public void testStrToByte() {
        String testStr = "ab";
        byte[] arr = testStr.getBytes(StandardCharsets.UTF_16);
        String resStr = new String(arr, StandardCharsets.UTF_16);
        assertEquals(testStr, resStr);
    }

    @Test
    public void testBytesToStr() {
        byte[] arr = new byte[] {97, 0, 98, 0, 99, 0, 100, 0, 101, 0, 102, 0, 103, 0};
        System.out.println(new String(arr, StandardCharsets.UTF_16LE));
    }

    @Test
    public void testIntNewByte() {
        System.out.println(ByteBuffer.wrap(new byte[] {0, 0, 103, 0}).getInt());
        int parsed = Integer.parseUnsignedInt("0000026368");
        byte[] test1 = ByteBuffer.allocate(4).putInt(parsed).array();
        System.out.println(Arrays.toString(test1));

        int test2 = ByteUtils.bytesToInt(test1, ByteOrder.BIG_ENDIAN);
        System.out.println(test2);
    }

    @Test
    public void testIntByte() {
        Random random = new Random();
        for (int i = 0; i < 1000000; i++) {
            int testI = random.nextInt();
            assertArrayEquals(ByteUtils.intToBytes(testI), ByteBuffer.allocate(4).putInt(testI).array());
        }
    }

    @Test
    public void testByteInt() {
        Random random = new Random();
        for (int i = 0; i < 1000000; i++) {
            byte[] bytes1 = new byte[4];
            random.nextBytes(bytes1);
            assertEquals(ByteUtils.bytesToInt(bytes1, 0), ByteBuffer.wrap(bytes1).getInt());
        }
    }

    @Test
    public void testByteLong() {
        long l = Long.MAX_VALUE;
        byte[] res = ByteUtils.longToBytes(l);
        assertEquals(ByteUtils.bytesToLong(res, 0), l);
    }

    @Test
    public void testByteLongs() {
        long l = Long.parseUnsignedLong("0000000001711302400");
        long l1 = Long.parseUnsignedLong("1711302400");
        byte[] lb = ByteUtils.longToBytes(l);
        byte[] l1b = ByteUtils.longToBytes(l1);
        System.out.println(Arrays.toString(lb));
        System.out.println(Arrays.toString(l1b));
        assertEquals(l, l1);
        assertArrayEquals(lb, l1b);
    }

    @Test
    public void testFormat() {
        long l = Long.MAX_VALUE;
        System.out.println(String.format(Locale.US,"%020d", l));
    }

    @Test
    public void testULong() {
        String testStr = "123131Hello World!";
        byte[] strBytes = testStr.getBytes(StandardCharsets.UTF_16);

        long longFromBytes = ByteUtils.bytesToLong(strBytes, 0);
        System.out.println(longFromBytes);
        String uLongStr = Long.toUnsignedString(longFromBytes);
        System.out.println(uLongStr);
        long parsedLong = Long.parseUnsignedLong(uLongStr);

        byte[] longArr = ByteUtils.longToBytes(parsedLong);
        String result = new String(longArr, StandardCharsets.UTF_16);
        System.out.println(result);
    }

    @Test
    public void testCharToInt() {
        String str = "abcфмсёЙ";
        System.out.println(str.charAt(7));
    }

}