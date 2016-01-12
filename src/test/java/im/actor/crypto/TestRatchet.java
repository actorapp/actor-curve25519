package im.actor.crypto;

import im.actor.crypto.ratchet.RatchetMasterSecret;
import im.actor.crypto.ratchet.RatchetPrivateKey;
import org.junit.Test;

import java.security.SecureRandom;

import static org.junit.Assert.assertArrayEquals;

public class TestRatchet {

    private SecureRandom random = new SecureRandom();

    @Test
    public void testRatchet() {
        RatchetPrivateKey aliceIdentity = generateKey();
        RatchetPrivateKey bobIdentity = generateKey();
        RatchetPrivateKey[] aliceEphermalKeys = generateKeys(10);
        RatchetPrivateKey[] bobEphermalKeys = generateKeys(10);

        byte[] alice_secret = RatchetMasterSecret.calculateMasterSecret(
                aliceIdentity,
                aliceEphermalKeys[0],
                bobIdentity,
                bobEphermalKeys[0]);

        byte[] bob_secret = RatchetMasterSecret.calculateMasterSecret(
                bobIdentity,
                bobEphermalKeys[0],
                aliceIdentity,
                aliceEphermalKeys[0]);

        assertArrayEquals(alice_secret, bob_secret);
    }

    private RatchetPrivateKey generateKey() {
        byte[] rnd = new byte[32];
        random.nextBytes(rnd);
        return new RatchetPrivateKey(Curve25519.keyGenPrivate(rnd));
    }

    private RatchetPrivateKey[] generateKeys(int count) {
        RatchetPrivateKey[] res = new RatchetPrivateKey[count];
        for (int i = 0; i < count; i++) {
            res[i] = generateKey();
        }
        return res;
    }

}
