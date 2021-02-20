package interfaces;

import utils.User;

import java.security.NoSuchAlgorithmException;

public interface IUserService {
    boolean addUser(String userName, String password, byte[] salt) throws NoSuchAlgorithmException;

    boolean deleteUser(String userName);

    User getUser(String userName);

    boolean isUserPresent(String userName);

    boolean isUserSaltPresent(String userName);

    byte[] getSalt(String userName);
}
