package im.actor.crypto.impl.curve25519;

public interface Sha512 {

  public void calculateDigest(byte[] out, byte[] in, long length);

}
