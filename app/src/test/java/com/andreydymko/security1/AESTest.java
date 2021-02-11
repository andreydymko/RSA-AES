package com.andreydymko.security1;

import com.andreydymko.security1.AES.AES;
import com.andreydymko.security1.AES.AESHelper;
import com.andreydymko.security1.AES.Galua;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.Assert.*;

public class AESTest {

    @Test
    public void shiftRowsTest() {
        int[][] arr = new int[][] {
                {0, 1, 2, 3},
                {4, 5, 6, 7},
                {8, 9, 10, 11},
                {12, 13, 14, 15}
        };
        AESHelper helper = new AESHelper(4, 8, 14, 4);
        helper.shiftRows(arr, true);
        System.out.println(Arrays.deepToString(arr));
    }

    @Test
    public void byteToHex() {
        byte test = (byte) 0xFA;
        System.out.println(test + "\n");
        System.out.println((int) (test >> 4) & 0x0F); // x
        System.out.println((int) test & 0x0F); // y
        System.out.println((test & 0xFF) / 0x10); // x
        System.out.println((test & 0xFF) % 0x10); // y
    }

    @Test
    public void intToByte() {
        System.out.println( (byte) (255) & 0xFF );
        System.out.println(0x100);
    }

    @Test
    public void testAES() {
        String inputStr = "угу\n" +
                "лза\n" +
                "Извеняюсь\n" +
                "8=D Android DeveloperСегодня, в 18:50\n" +
                "CAT\n" +
                ":blyat:\n" +
                "Персона ЩитпостерСегодня, в 18:50\n" +
                "Салам\n" +
                "8=D Android DeveloperСегодня, в 18:51\n" +
                "лол\n" +
                "у нее батю Салам зовут\n" +
                "типа когда ему говорят привет\n" +
                "он отвечает \"че звал?\"\n" +
                "Персона ЩитпостерСегодня, в 18:51\n" +
                "Салам, Салам\n" +
                "8=D Android DeveloperСегодня, в 18:52\n" +
                "можно было и 1 раз позвать\n" +
                ":clown~1:\n" +
                "Персона ЩитпостерСегодня, в 19:04\n" +
                "сидишь там один\n" +
                "грустишь\n" +
                "на андроид игрушки делаешь\n" +
                "Персона ЩитпостерСегодня, в 19:13\n" +
                "PHOGGERS\n" +
                "\n" +
                "8=D Android DeveloperСегодня, в 19:15\n" +
                "@Персона Щитпостер крч\n" +
                "завтра пройди ластовый тестик\n" +
                "я за тебя ластовю лабу попробую сделать\n" +
                "це ок?";

        AES aes = new AES(256);
        byte[] outCrypt = new byte[16];
        byte[] key = "abcdefghjklertyuiovbdzxcm".getBytes(StandardCharsets.ISO_8859_1);
        System.out.println(key.length);
        byte[] input = inputStr.getBytes(StandardCharsets.UTF_16);
        System.out.println(input.length);
        System.out.println(Arrays.toString(input));

        byte[] encrypted = aes.encrypt(input, key);

        byte[] decrypted = aes.decrypt(encrypted, key);

        System.out.println("res:");
        System.out.println(Arrays.toString(decrypted));
        String resStr = new String(decrypted, StandardCharsets.UTF_16);
        System.out.println(resStr);

        assertEquals(resStr, inputStr);
    }

    @Test
    public void testSmt() {
        System.out.println((byte) 191);
    }

    @Test
    public void testGalua() {
        int val = 15;
        System.out.println(Galua.multi(val, 0x02));
        System.out.println(Galua.multi(val, 0x03));
        System.out.println(Galua.multi(val, 0x09));
        System.out.println(Galua.multi(val, 0x0b));
        System.out.println(Galua.multi(val, 0x0d));
        System.out.println(Galua.multi(val, 0x0e));
    }
}
