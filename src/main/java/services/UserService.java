package services;

import exception.AuthenticationException;
import exception.UserAlreadyExistsException;
import exception.UserDoesntExistException;
import interfaces.IAuthenticationService;
import interfaces.ISaltService;
import interfaces.IUserService;
import utils.AuthenticationToken;
import utils.User;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class UserService implements IUserService {
    private final IAuthenticationService authenticationService;
    private final ISaltService saltService;
    private final List<User> userCache = new ArrayList<>();
    private final Map<String, byte[]> userSaltCache = new HashMap<>();

    public UserService(IAuthenticationService authenticationService, ISaltService saltService) {
        this.authenticationService = authenticationService;
        this.saltService = saltService;
    }

    @Override
    public User addUser(String userName, String password) throws UserAlreadyExistsException {
        byte[] salt = saltService.getSalt();
        String saltedPassword = saltService.get_SHA_1_SecurePassword(password, salt);

        userSaltCache.put(userName, salt);
        User user = new User(userName, saltedPassword);
        if (!userCache.contains(user)) {
            userCache.add(user);
            return user;
        }
        throw new UserAlreadyExistsException("User "+ user +" already exists");
    }

    @Override
    public void deleteUser(User user) throws UserDoesntExistException {
        if (!userCache.remove(user))
            throw new UserDoesntExistException("User "+ user + " does not exist");
    }

    @Override
    public boolean containsUser(User user) {
        return userCache.contains(user);
    }

    @Override
    public AuthenticationToken authenticate(String userName, String password) throws AuthenticationException {
        String saltedPassword = saltService.get_SHA_1_SecurePassword(password, saltService.getSalt());
        User userToAuthenticate = new User(userName, saltedPassword);
        if (userCache.contains(userToAuthenticate)) {
            return authenticationService.getAuthenticationToken(userToAuthenticate);
        }
        throw new AuthenticationException("Failed to authenticate as user " + userName + " not present");
    }
}
