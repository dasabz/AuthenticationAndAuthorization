package interfaces;

import exception.AuthenticationException;
import exception.UserAlreadyExistsException;
import exception.UserDoesntExistException;
import utils.AuthenticationToken;
import utils.User;

/*
    This microservice helps in adding and deleting users and also facilitates the authentication of a user once the user is created
     with the help of the authentication microservice
 */
public interface IUserService {
    User addUser(String userName, String password) throws UserAlreadyExistsException;

    void deleteUser(User user) throws UserDoesntExistException;

    boolean containsUser(User user);

    AuthenticationToken authenticate(String userName, String password) throws AuthenticationException;
}
