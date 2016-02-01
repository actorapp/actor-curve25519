package im.actor.crypto.primitives.kuznechik;

import im.actor.crypto.primitives.util.Pack;
import org.junit.Test;

import java.security.SecureRandom;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class TestKuznechikFast {

    @Test
    public void testKey() {
        SecureRandom random = new SecureRandom(new byte[]{1, 2, 3, 4, 5});
        for (int j = 0; j < 1000; j++) {
            byte[] key = new byte[32];
            random.nextBytes(key);

            KuzIntKey key1 = KuznechikCipher.convertKey(key);
            int[][] key2 = KuznechikFastEngine.convertKey(key);
            for (int i = 0; i < 10; i++) {
                for (int k = 0; k < 4; k++) {
                    assertEquals(key2[i][k], Pack.bigEndianToInt(key1.getK()[i].getB(), k * 4));
                }
            }
        }
    }

    @Test
    public void testKuz() {
        SecureRandom random = new SecureRandom(new byte[]{1, 2, 3, 4, 5});
        for (int j = 0; j < 100; j++) {
            byte[] key = new byte[32];

            random.nextBytes(key);

            KuznechikCipher slowCipher = new KuznechikCipher(key);
            KuznechikFastEngine fastCipher = new KuznechikFastEngine(key);

            byte[] data = new byte[16];
            byte[] data2 = new byte[16];
            byte[] data3 = new byte[16];
            byte[] data4 = new byte[16];
            byte[] data5 = new byte[16];
            for (int i = 0; i < 100; i++) {
                random.nextBytes(data);
                fastCipher.encryptBlock(data, 0, data2, 0);
                slowCipher.encryptBlock(data, 0, data5, 0);
                slowCipher.decryptBlock(data2, 0, data3, 0);
                fastCipher.decryptBlock(data2, 0, data4, 0);
                // slowCipher.decryptBlock(data2, 0, data4, 0);

                assertArrayEquals(data, data3);
                assertArrayEquals(data, data4);
                assertArrayEquals(data2, data5);
            }
        }
    }

    @Test
    public void splitKuzL() {

        byte[][][] table = new byte[16][256][16];
        for (int index = 0; index < 16; index++) {
            for (int i = 0; i < 256; i++) {
                table[index][i][index] = (byte) i;
                KuznechikFastEngine.kuz_l(table[index][i]);
            }
        }

        SecureRandom random = new SecureRandom(new byte[]{1, 2, 3, 4, 5});
        for (int it = 0; it < 1000; it++) {
            byte[] data = new byte[16];
            byte[] fullRes = new byte[16];
            byte[] fullRes2 = new byte[16];
            // byte[][] data1 = new byte[16][16];
            random.nextBytes(data);

            for (int i = 0; i < 16; i++) {
                fullRes[i] = data[i];
            }
            KuznechikFastEngine.kuz_l(fullRes);

            for (int i = 0; i < 16; i++) {
                for (int j = 0; j < 16; j++) {
                    fullRes2[i] = (byte) ((fullRes2[i] & 0xFF) ^
                            (table[j][data[j] & 0xFF][i] & 0xFF));
                }
            }

            assertArrayEquals(fullRes, fullRes2);
        }
    }

    @Test
    public void generateTable() {
        byte[][][] table = new byte[16][256][16];
        byte[] tmp = new byte[16];
        for (int index = 0; index < 16; index++) {
            for (int i = 0; i < 256; i++) {
                table[index][i][index] = (byte) i;

                KuznechikFastEngine.kuz_l(table[index][i]);
            }
        }

        SecureRandom random = new SecureRandom(new byte[]{1, 2, 3, 4, 5});
        byte[] rawKey = new byte[32];
        random.nextBytes(rawKey);
        byte[] plainText = new byte[16];
        byte[] cipherText = new byte[16];
        byte[] cipherText2 = new byte[16];
        byte[] plainText2 = new byte[16];
        // random.nextBytes(plainText);
        KuznechikFastEngine fastEngine = new KuznechikFastEngine(rawKey);
        int[][] key = fastEngine.getKey();

        // Test Encryption

        int[] x = new int[4];
        Pack.bigEndianToInt(plainText, 0, x);
        for (int i = 0; i < 9; i++) {

            x[0] = x[0] ^ key[i][0];
            x[1] = x[1] ^ key[i][1];
            x[2] = x[2] ^ key[i][2];
            x[3] = x[3] ^ key[i][3];

            x[0] = (KuznechikTables.kuz_pi[x[0] & 0xFF] & 0xFF)
                    + ((KuznechikTables.kuz_pi[(x[0] >> 8) & 0xFF] & 0xFF) << 8)
                    + ((KuznechikTables.kuz_pi[(x[0] >> 16) & 0xFF] & 0xFF) << 16)
                    + ((KuznechikTables.kuz_pi[(x[0] >> 24) & 0xFF] & 0xFF) << 24);

            x[1] = (KuznechikTables.kuz_pi[x[1] & 0xFF] & 0xFF)
                    + ((KuznechikTables.kuz_pi[(x[1] >> 8) & 0xFF] & 0xFF) << 8)
                    + ((KuznechikTables.kuz_pi[(x[1] >> 16) & 0xFF] & 0xFF) << 16)
                    + ((KuznechikTables.kuz_pi[(x[1] >> 24) & 0xFF] & 0xFF) << 24);

            x[2] = (KuznechikTables.kuz_pi[x[2] & 0xFF] & 0xFF)
                    + ((KuznechikTables.kuz_pi[(x[2] >> 8) & 0xFF] & 0xFF) << 8)
                    + ((KuznechikTables.kuz_pi[(x[2] >> 16) & 0xFF] & 0xFF) << 16)
                    + ((KuznechikTables.kuz_pi[(x[2] >> 24) & 0xFF] & 0xFF) << 24);

            x[3] = (KuznechikTables.kuz_pi[x[3] & 0xFF] & 0xFF)
                    + ((KuznechikTables.kuz_pi[(x[3] >> 8) & 0xFF] & 0xFF) << 8)
                    + ((KuznechikTables.kuz_pi[(x[3] >> 16) & 0xFF] & 0xFF) << 16)
                    + ((KuznechikTables.kuz_pi[(x[3] >> 24) & 0xFF] & 0xFF) << 24);

            byte[] xUNpacked = Pack.intToBigEndian(x);
            byte[] a = new byte[16];
            for (int ind = 0; ind < 16; ind++) {
                for (int j = 0; j < 16; j++) {
                    a[ind] = (byte) ((a[ind] & 0xFF) ^
                            (table[j][xUNpacked[j] & 0xFF][ind] & 0xFF));
                }
            }

            Pack.bigEndianToInt(a, 0, x);
        }

        x[0] = x[0] ^ key[9][0];
        x[1] = x[1] ^ key[9][1];
        x[2] = x[2] ^ key[9][2];
        x[3] = x[3] ^ key[9][3];
        Pack.intToBigEndian(x, cipherText, 0);

        fastEngine.encryptBlock(plainText, 0, cipherText2, 0);
        fastEngine.decryptBlock(cipherText2, 0, plainText2, 0);

        assertArrayEquals(plainText, plainText2);
        assertArrayEquals(cipherText, cipherText2);
    }
}
