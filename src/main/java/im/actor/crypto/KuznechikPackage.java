package im.actor.crypto;

public class KuznechikPackage {

    byte[] plainPackage;
    byte[] mac;
    byte[] padding;

    public KuznechikPackage(byte[] plainPackage, byte[] mac, byte[] padding) {
        this.plainPackage = plainPackage;
        this.mac = mac;
        this.padding = padding;
    }

    public byte[] getPlainPackage() {
        return plainPackage;
    }

    public byte[] getMac() {
        return mac;
    }

    public byte[] getPadding() {
        return padding;
    }
}
