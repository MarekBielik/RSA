package exceptions;

/**
 * Created by marek on 3/13/16.
 */
public class RSAException extends Exception {
    private String eMessage;

    public RSAException(String eMessage) {
        this.eMessage = eMessage;
    }

    public String geteMessage() {
        return eMessage;
    }
}
