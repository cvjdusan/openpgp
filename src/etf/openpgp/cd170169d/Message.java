package etf.openpgp.cd170169d;

import java.util.List;

public class Message {
    String msg;
    List<String> verifiers;
    List<Long> keysNotFound;
    boolean isVerified;
    boolean sign;

    public Message(String msg, List<String> verifiers, List<Long> keysNotFound, boolean verified, boolean sign) {
        this.msg = msg;
        this.verifiers = verifiers;
        this.keysNotFound = keysNotFound;
        this.isVerified = verified;
        this.sign = sign;
    }
}
