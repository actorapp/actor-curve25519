package im.actor.crypto;

import im.actor.crypto.blocks.Curve25519KeyPair;
import im.actor.crypto.blocks.impl.Curve25519;

import java.security.*;

public class ActorCrypto {

    public static Curve25519KeyPair keyGen(SecureRandom random) {
        byte[] privateKey = new byte[32];
        byte[] privateSigningKey = new byte[32];
        byte[] publicKey = new byte[32];
        random.nextBytes(privateKey);
        Curve25519.keygen(publicKey, privateSigningKey, privateKey);
        return new Curve25519KeyPair(publicKey, privateSigningKey, privateKey);
    }
}