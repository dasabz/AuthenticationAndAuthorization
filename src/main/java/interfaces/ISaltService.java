package interfaces;
/*
This microservice helps in providing the salt for the password in order to be stored in a safe way
 */
public interface ISaltService {
    byte[] getSalt();

    String get_SHA_1_SecurePassword(String passwordToHash, byte[] salt);
}
