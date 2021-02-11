package com.andreydymko.security1.AES;

import java.text.MessageFormat;

public class Galua {
    public static int sum(int val1, int val2) {
        return val1 ^ val2;
    }

    public static int multi(int val, int multiplier) {
        switch (multiplier) {
            case 0x00:
                return 0;
            case 0x01:
                return val;
            case 0x02:
                return (val < 0x80 ? val << 1 : (val << 1) ^ 0x1b) % 0x100;
            case 0x03:
                return multi(val, 0x02) ^ val;
            case 0x09:
                return multi(multi(multi(val, 0x02), 0x02), 0x02) ^ val;
            case 0x0b:
                return multi(multi(multi(val, 0x02), 0x02), 0x02) ^ multi(val, 0x02) ^ val;
            case 0x0d:
                return multi(multi(multi(val, 0x02), 0x02), 0x02) ^ multi(multi(val, 0x02), 0x02) ^ val;
            case 0x0e:
                return multi(multi(multi(val, 0x02), 0x02), 0x02) ^ multi(multi(val, 0x02), 0x02) ^ multi(val, 0x02);
            default:
                throw new IllegalArgumentException(MessageFormat.format("Multiplier {0} is not supported", multiplier));
        }
    }
}
