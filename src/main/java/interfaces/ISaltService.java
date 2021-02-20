package interfaces;

import java.security.NoSuchAlgorithmException;

public interface ISaltService {
    byte[] getSalt() throws NoSuchAlgorithmException;

    String get_SHA_1_SecurePassword(String passwordToHash, byte[] salt);
}
