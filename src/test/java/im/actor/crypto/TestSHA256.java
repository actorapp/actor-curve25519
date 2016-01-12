package im.actor.crypto;

import im.actor.crypto.primitives.digest.SHA256Digest;
import org.junit.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static org.junit.Assert.assertArrayEquals;

public class TestSHA256 {

    private static byte[][] messages = {
            "".getBytes(),
            "a".getBytes(),
            "abc".getBytes(),
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".getBytes()
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
            byte[] data = messages[i];
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

    @Test
    public void testRandom() throws NoSuchAlgorithmException {
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < 100000; i++) {
            SHA256Digest sha256Digest = new SHA256Digest();
            byte[] data = new byte[128];
            random.nextBytes(data);

            sha256Digest.reset();
            sha256Digest.update(data, 0, data.length);
            byte[] res = new byte[32];
            sha256Digest.doFinal(res, 0);

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] res2 = md.digest(data);
            assertArrayEquals(res, res2);
        }
    }
}