package im.actor.crypto;

import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;

public class TestAgreements {

    @Test
    public void testRandomAgreements() {
        Curve25519 curve25519 = new Curve25519();
        for (int i = 0; i < 1000; i++) {
            Curve25519KeyPair aliceKey = curve25519.keyGen();
            Curve25519KeyPair bobKey = curve25519.keyGen();

            byte[] aliceShared = curve25519.calculateAgreement(aliceKey.getPrivateKey(), bobKey.getPublicKey());
            byte[] bobShared = curve25519.calculateAgreement(bobKey.getPrivateKey(), aliceKey.getPublicKey());

            assertArrayEquals(aliceShared, bobShared);
        }
    }
}