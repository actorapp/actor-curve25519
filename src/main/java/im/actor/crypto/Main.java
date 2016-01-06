package im.actor.crypto;

import im.actor.crypto.blocks.Curve25519KeyPair;
import im.actor.crypto.blocks.impl.Curve25519;
import im.actor.crypto.blocks.PFR;
import im.actor.crypto.blocks.SHA256;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

public class Main {
    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecureRandom random = new SecureRandom();

        Curve25519KeyPair serverFullKey = ActorCrypto.keyGen(random);
        Curve25519KeyPair clientFullKey = ActorCrypto.keyGen(random);
        byte[] clientNonce = new byte[32];
        random.nextBytes(clientNonce);
        byte[] serverNonce = new byte[32];
        random.nextBytes(serverNonce);

        //
        // Step 3: ResponseDoDH
        //

        byte[] pre_master_secret = new byte[32];
        Curve25519.curve(pre_master_secret, serverFullKey.getPrivateKey(), clientFullKey.getPublicKey());
        byte[] master_secret = PFR.calculate(pre_master_secret, "master secret", Tools.merge(clientNonce, serverNonce));
        byte[] verify = PFR.calculate(master_secret, "client finished", Tools.merge(clientNonce, serverNonce));

        // TODO: Reimplment signing
        byte[] verify_sign = new byte[64];
        byte[] signRandom = SHA256.calc(master_secret);// To avoid using PRNG
        // random.nextBytes(signRandom);
        Curve25519.sign(verify_sign, SHA256.calc(verify), signRandom, serverFullKey.getPrivateSigningKey());

        //
        // Step 4: Checking verify
        //
        byte[] sigPubKey = new byte[64];
        Curve25519.verify(sigPubKey, verify_sign, SHA256.calc(verify), serverFullKey.getPublicKey());
    }
}
