package etf.openpgp.cd170169d;

import org.bouncycastle.openpgp.PGPKeyRing;

public class Key {
    private String name;
    private String email;
    private String id;
    private PGPKeyRing ring;

    public Key(String name, String email, String id, PGPKeyRing ring) {
        this.name = name;
        this.email = email;
        this.id = id;
        this.ring = ring;
    }

    public String getName() {
        return name;
    }

    public Long getLongKeyId(){
        return ring.getPublicKey().getKeyID();
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }
}
