package etf.openpgp.cd170169d;

import java.util.List;

/**
 * Klasa koja sadrzi poruku koju je potrebno prikazati prilikom primanja iste
 *
 */

public class Message {
    String msg;
    List<String> verifiers;
    List<Long> keysNotFound;
    int alg;
    boolean isVerified;
    boolean sign;

    public Message(String msg, List<String> verifiers, List<Long> keysNotFound, boolean verified, boolean sign, int alg) {
        this.msg = msg;
        this.verifiers = verifiers;
        this.keysNotFound = keysNotFound;
        this.isVerified = verified;
        this.sign = sign;
        this.alg = alg;
    }
}
