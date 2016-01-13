package im.actor.crypto;

import im.actor.crypto.primitives.aes.AESFastEngine;
import im.actor.crypto.primitives.digest.SHA256;
import im.actor.crypto.primitives.hmac.HMAC;
import im.actor.crypto.primitives.kdf.HKDF;
import im.actor.crypto.primitives.modes.CBCBlockCipher;
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

        byte[] message = "Hey!Hey!Hey!Hey!".getBytes(); // Temporarry without padding

        RatchetMessage encMessage;
        {
            RatchetMessageKey ratchetMessageKey =
                    RatchetMessageKey.buildKey(alice_root_chain_key, 0);

            byte[] iv = new byte[16];
            random.nextBytes(iv);

            CBCBlockCipher blockCipher = new CBCBlockCipher(new AESFastEngine(ratchetMessageKey.getCipherKey()));
            byte[] res = blockCipher.encrypt(iv, message);

            byte[] mac = new byte[32];
            HMAC msgHmac = new HMAC(ratchetMessageKey.getMacKey(), new SHA256());
            msgHmac.update(res, 0, res.length);
            msgHmac.doFinal(mac, 0);

            encMessage = new RatchetMessage(
                    0, 0,
                    aliceEphermalKeys[1].getKey(),
                    bobEphermalKeys[1].getKey(),
                    0,
                    iv, res, mac);
        }

        // Decryption
        {
            RatchetMessageKey ratchetMessageKey =
                    RatchetMessageKey.buildKey(bob_root_chain_key, 0);

            byte[] mac = new byte[32];
            HMAC msgHmac = new HMAC(ratchetMessageKey.getMacKey(), new SHA256());
            msgHmac.update(encMessage.getCipherMessage(), 0, encMessage.getCipherMessage().length);
            msgHmac.doFinal(mac, 0);

            assertArrayEquals(mac, encMessage.getMac());

            CBCBlockCipher blockCipher = new CBCBlockCipher(new AESFastEngine(ratchetMessageKey.getCipherKey()));
            byte[] data = blockCipher.decrypt(encMessage.getIv(), encMessage.getCipherMessage());

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
