package interfaces;

import exception.*;
import utils.AuthenticationToken;
import utils.Role;
import utils.User;

import java.util.List;
/*
    This facade is basically a manager which coordinates the various microservices.
 */
public interface IAuthenticationManagerFacade {
    User createUser(String userName, String password) throws UserAlreadyExistsException;

    void deleteUser(User user) throws UserDoesntExistException;

    void createRole(Role role) throws RoleAlreadyExistsException;

    void deleteRole(Role role) throws RoleDoesNotExistException;

    void addRoleToUser(User user, Role role) throws AuthenticationException;

    AuthenticationToken authenticate(String userName, String password) throws AuthenticationException;

    AuthenticationToken authenticateAnonymous() throws AuthenticationException;

    void invalidatePreExpiredToken(AuthenticationToken authenticationToken) throws AuthenticationException;

    boolean checkRole(User user, Role role) throws AuthenticationException;

    List<Role> getAllRoles(User user) throws AuthenticationException;

    boolean containsUser(User expectedUser);

    boolean containsRole(Role normalUser);
}
