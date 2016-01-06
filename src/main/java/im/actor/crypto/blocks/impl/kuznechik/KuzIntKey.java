package im.actor.crypto.blocks.impl.kuznechik;

class KuzIntKey {

    private final Kuz128[] k;

    public KuzIntKey(Kuz128[] k) {
        this.k = k;
    }

    public KuzIntKey() {
        this.k = new Kuz128[10];
        for (int i = 0; i < 10; i++) {
            k[i] = new Kuz128();
        }
    }

    public Kuz128[] getK() {
        return k;
    }
}
