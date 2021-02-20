package interfaces;

import utils.AuthenticationToken;
import utils.AuthenticationStatus;
import utils.UserRole;

import java.security.NoSuchAlgorithmException;
import java.util.List;
/*

 */
public interface IAuthenticationManagerFacade {
    AuthenticationStatus createUser(String userName, String password) throws NoSuchAlgorithmException;

    AuthenticationStatus deleteUser(String userName);

    AuthenticationStatus createRole(UserRole userRole);

    AuthenticationStatus deleteRole(UserRole userRole);

    AuthenticationStatus addRoleToUser(String userName, UserRole userRole);

    AuthenticationToken authenticate(String userName, String password) throws Exception;

    AuthenticationToken authenticateAnonymous() throws Exception;

    void invalidatePreExpiredToken(AuthenticationToken authenticationToken) throws Exception;

    boolean checkRole(AuthenticationToken authenticationToken, UserRole role) throws Exception;

    List<UserRole> getAllRoles(AuthenticationToken authenticationToken) throws Exception;
}
