package services;

import utils.User;
import interfaces.IUserService;

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class UserService implements IUserService {
    private final Map<String, User> userCache = new HashMap<>();
    private final Map<String, byte[]> userSaltCache = new HashMap<>();

    public UserService() {
    }

    private boolean isValidUser(User user) {
        return userCache.containsKey(user.getUserName());
    }

    @Override
    public boolean addUser(String userName, String password, byte[] salt) throws NoSuchAlgorithmException {
        userSaltCache.put(userName, salt);
        User user = new User(userName, password);
        if (!isValidUser(user)) {
            userCache.put(user.getUserName(), user);
            return true;
        }
        return false;
    }

    @Override
    public boolean deleteUser(String userName) {
        if (userCache.containsKey(userName)) {
            userCache.remove(userName);
            return true;
        }
        return false;
    }

    @Override
    public User getUser(String userName) {
        return userCache.get(userName);
    }

    @Override
    public boolean isUserPresent(String userName) {
        return userCache.containsKey(userName);
    }

    @Override
    public boolean isUserSaltPresent(String userName) {
        return userSaltCache.containsKey(userName);
    }

    @Override
    public byte[] getSalt(String userName) {
        return userSaltCache.get(userName);
    }
}
