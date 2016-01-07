package im.actor.crypto;

import im.actor.crypto.primitives.digest.SHA256Digest;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;

public class TestSHA256 {

    private static String[] messages = {
            "",
            "a",
            "abc",
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    };

    private static String[] digests = {
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    };

    @Test
    public void testSHA256() {
        SHA256Digest sha256Digest = new SHA256Digest();
        for (int i = 0; i < messages.length; i++) {
            byte[] dest = new byte[32];
            byte[] data = messages[i].getBytes();
            sha256Digest.reset();
            sha256Digest.update(data, 0, data.length);
            sha256Digest.doFinal(dest, 0);
            byte[] dest2 = new byte[32];
            for (int j = 0; j < 32; j++) {
                String dg = digests[i].charAt(j * 2) + "" + digests[i].charAt(j * 2 + 1);
                dest2[j] = (byte) Integer.parseInt(dg, 16);
            }
            assertArrayEquals(dest2, dest);
        }
    }
}