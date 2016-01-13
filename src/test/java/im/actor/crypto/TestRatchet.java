package im.actor.crypto;

import im.actor.crypto.box.ActorBox;
import im.actor.crypto.box.ActorBoxKey;
import im.actor.crypto.primitives.util.ByteStrings;
import im.actor.crypto.ratchet.*;
import org.junit.Test;

import java.security.SecureRandom;

import static org.junit.Assert.assertArrayEquals;

public class TestRatchet {

    private SecureRandom random = new SecureRandom();

    @Test
    public void testRatchet() throws IntegrityException {
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

        byte[] alice_root_chain_key = RatchetRootChainKey.makeRootChainKey(
                aliceEphermalKeys[1], bobEphermalKeys[1], alice_secret);

        byte[] bob_root_chain_key = RatchetRootChainKey.makeRootChainKey(
                bobEphermalKeys[1], aliceEphermalKeys[1], alice_secret);

        assertArrayEquals(alice_root_chain_key, bob_root_chain_key);

        // Encryption

        byte[] message = "Hey! Let's encrypt!".getBytes();

        RatchetMessage encMessage;
        {
            ActorBoxKey ratchetMessageKey = RatchetMessageKey.buildKey(alice_root_chain_key, 0);

            byte[] header = ByteStrings.merge(
                    ByteStrings.longToBytes(0), /*Alice Initial Ephermal*/
                    ByteStrings.longToBytes(0), /*Bob Initial Ephermal*/
                    aliceEphermalKeys[1].getKey(),
                    bobEphermalKeys[1].getKey(),
                    ByteStrings.intToBytes(0)); /* Message Index */

            byte[] random32 = new byte[32];
            random.nextBytes(random32);

            byte[] data = ActorBox.closeBox(header, message, random32, ratchetMessageKey);

            encMessage = new RatchetMessage(0, 0, aliceEphermalKeys[1].getKey(), bobEphermalKeys[1].getKey(), 0, data);
        }

        // Decryption
        {
            ActorBoxKey ratchetMessageKey = RatchetMessageKey.buildKey(bob_root_chain_key, 0);

            byte[] header = ByteStrings.merge(
                    ByteStrings.longToBytes(encMessage.getSenderEphermalId()), /*Alice Initial Ephermal*/
                    ByteStrings.longToBytes(encMessage.getReceiverEphermalId()), /*Bob Initial Ephermal*/
                    encMessage.getSenderEphermal(),
                    encMessage.getReceiverEphermal(),
                    ByteStrings.intToBytes(encMessage.getMessageIndex())); /* Message Index */

            byte[] data = ActorBox.openBox(header,encMessage.getCipherBox(),ratchetMessageKey);

            assertArrayEquals(data, message);
        }
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
