package im.actor.crypto;

import im.actor.crypto.primitives.digest.MD5;
import im.actor.crypto.primitives.digest.SHA256Digest;
import im.actor.crypto.tools.Hex;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;

public class TestMD5 {

    static final String[] messages =
            {
                    "",
                    "a",
                    "abc",
                    "abcdefghijklmnopqrstuvwxyz"
            };

    static final String[] digests =
            {
                    "d41d8cd98f00b204e9800998ecf8427e",
                    "0cc175b9c0f1b6a831c399e269772661",
                    "900150983cd24fb0d6963f7d28e17f72",
                    "c3fcd3d76192e4007dfb496cca67e13b"
            };

    @Test
    public void testMD5() {
        MD5 md5Digest = new MD5();
        for (int i = 0; i < messages.length; i++) {
            byte[] dest = new byte[16];
            byte[] data = messages[i].getBytes();
            md5Digest.reset();
            md5Digest.update(data, 0, data.length);
            md5Digest.doFinal(dest, 0);
            byte[] dest2 = new byte[16];
            for (int j = 0; j < 16; j++) {
                String dg = digests[i].charAt(j * 2) + "" + digests[i].charAt(j * 2 + 1);
                dest2[j] = (byte) Integer.parseInt(dg, 16);
            }
            assertArrayEquals(dest2, dest);
        }
    }
}
