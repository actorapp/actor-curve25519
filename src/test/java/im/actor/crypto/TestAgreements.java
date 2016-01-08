package im.actor.crypto;

import org.junit.Test;

import java.security.SecureRandom;

import static org.junit.Assert.assertArrayEquals;

public class TestAgreements {

    private SecureRandom secureRandom = new SecureRandom();

    @Test
    public void testRandomAgreements() {
        for (int i = 0; i < 1000; i++) {
            byte[] randomBytes = new byte[32];
            secureRandom.nextBytes(randomBytes);
            Curve25519KeyPair aliceKey = Curve25519.keyGen(randomBytes);
            secureRandom.nextBytes(randomBytes);
            Curve25519KeyPair bobKey = Curve25519.keyGen(randomBytes);

            byte[] aliceShared = Curve25519.calculateAgreement(aliceKey.getPrivateKey(), bobKey.getPublicKey());
            byte[] bobShared = Curve25519.calculateAgreement(bobKey.getPrivateKey(), aliceKey.getPublicKey());

            assertArrayEquals(aliceShared, bobShared);
        }
    }
}