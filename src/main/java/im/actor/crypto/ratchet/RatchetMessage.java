package im.actor.crypto.ratchet;

public class RatchetMessage {
    private long senderEphermalId;
    private long receiverEphermalId;
    private byte[] senderEphermal;
    private byte[] receiverEphermal;
    private int messageIndex;
    private byte[] iv;
    private byte[] cipherMessage;
    private byte[] mac;

    public RatchetMessage(long senderEphermalId, long receiverEphermalId, byte[] senderEphermal, byte[] receiverEphermal,
                          int messageIndex,
                          byte[] iv, byte[] cipherMessage, byte[] mac) {
        this.senderEphermalId = senderEphermalId;
        this.receiverEphermalId = receiverEphermalId;
        this.senderEphermal = senderEphermal;
        this.receiverEphermal = receiverEphermal;
        this.messageIndex = messageIndex;
        this.iv = iv;
        this.cipherMessage = cipherMessage;
        this.mac = mac;
    }

    public long getSenderEphermalId() {
        return senderEphermalId;
    }

    public long getReceiverEphermalId() {
        return receiverEphermalId;
    }

    public byte[] getSenderEphermal() {
        return senderEphermal;
    }

    public byte[] getReceiverEphermal() {
        return receiverEphermal;
    }

    public byte[] getIv() {
        return iv;
    }

    public byte[] getCipherMessage() {
        return cipherMessage;
    }

    public byte[] getMac() {
        return mac;
    }

    public int getMessageIndex() {
        return messageIndex;
    }
}
