package com.andreydymko.security1;

public class VigenereCipher {
    private final static String TAG = VigenereCipher.class.getName();
    private final static String alphabet = "abcdefghijklmnopqrstuvwxyzабвгдеёжзийклмнопрстуфхцчшщъыьэюя0123456789";
    private final static String whitelist = "`~!@#$%^&*()-_=+\\|]}[{;:'\",<.>/?\t\n\r ";

    private VigenereCipher() {}

    public static String encryptStr(final String input, final String key) {
        if (key.isEmpty() || input.isEmpty()) return input;
        StringBuilder sb = new StringBuilder(input.length());
        int inputIdx, keyIdx;
        for (int i = 0; i < input.length(); i++) {
            if (whitelist.indexOf(input.charAt(i)) == -1) {
                inputIdx = alphabet.indexOf(input.charAt(i));
                keyIdx = alphabet.indexOf(key.charAt(i % key.length()));
                if (inputIdx == -1 || keyIdx == -1) {
                    sb.append(input.charAt(i));
                } else {
                    sb.append(alphabet.charAt((inputIdx + keyIdx) % alphabet.length()));
                }
            } else {
                sb.append(input.charAt(i));
            }
        }
        return sb.toString();
    }

    public static String decryptStr(final String input, final String key) {
        if (key.isEmpty() || input.isEmpty()) return input;
        StringBuilder sb = new StringBuilder(input.length());
        int inputIdx, keyIdx;
        for (int i = 0; i < input.length(); i++) {
            if (whitelist.indexOf(input.charAt(i)) == -1) {
                inputIdx = alphabet.indexOf(input.charAt(i));
                keyIdx = alphabet.indexOf(key.charAt(i % key.length()));
                if (inputIdx == -1 || keyIdx == -1) {
                    sb.append(input.charAt(i));
                } else {
                    sb.append(alphabet.charAt((inputIdx + alphabet.length() - keyIdx) % alphabet.length()));
                }
            } else {
                sb.append(input.charAt(i));
            }
        }
        return sb.toString();
    }
}
