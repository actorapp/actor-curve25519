package im.actor.crypto.blocks;

import java.security.SecureRandom;

public class Curve25519 {

    private SecureRandom random = new SecureRandom();

    /**
     * Generating KeyPair
     *
     * @return generated key pair
     */
    public synchronized Curve25519KeyPair keyGen() {
        byte[] privateKey = keyGenPrivate();
        byte[] publicKey = keyGenPublic(privateKey);
        return new Curve25519KeyPair(publicKey, privateKey);
    }

    /**
     * Generating private key. Source: https://cr.yp.to/ecdh.html
     *
     * @return generated private key
     */
    public synchronized byte[] keyGenPrivate() {
        byte[] privateKey = new byte[32];
        random.nextBytes(privateKey);
        privateKey[0] &= 248;
        privateKey[31] &= 127;
        privateKey[31] |= 64;
        return privateKey;
    }

    /**
     * Building public key with private key
     *
     * @param privateKey private key
     * @return generated public key
     */
    public synchronized byte[] keyGenPublic(byte[] privateKey) {
        byte[] publicKey = new byte[32];
        im.actor.crypto.blocks.impl.Curve25519.core(publicKey, null, privateKey, null);
        return publicKey;
    }

    /**
     * Calculating DH agreement
     *
     * @param ourPrivate  Our Private Key
     * @param theirPublic Theirs Public key
     * @return calculated agreement
     */
    public synchronized byte[] calculateAgreement(byte[] ourPrivate, byte[] theirPublic) {
        byte[] res = new byte[32];
        im.actor.crypto.blocks.impl.Curve25519.curve(res, ourPrivate, theirPublic);
        return res;
    }
}