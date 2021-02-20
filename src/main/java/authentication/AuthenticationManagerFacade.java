package authentication;

import services.AuthenticationService;
import services.RoleService;
import services.SaltService;
import services.UserService;
import utils.User;
import interfaces.IAuthenticationManagerFacade;
import utils.AuthenticationToken;
import utils.AuthenticationStatus;
import utils.UserRole;

import java.security.NoSuchAlgorithmException;
import java.util.List;

public class AuthenticationManagerFacade implements IAuthenticationManagerFacade {
    private final UserService userService;
    private final RoleService roleService;
    private final SaltService saltService;
    private final AuthenticationService authenticationService;
    private final boolean isAnonymousUserSupported ;
    public AuthenticationManagerFacade(UserService userService, RoleService roleService, SaltService saltService, AuthenticationService authenticationService, boolean isAnonymousUserSupported){
        this.userService              = userService;
        this.roleService              = roleService;
        this.saltService              = saltService;
        this.authenticationService    = authenticationService;
        this.isAnonymousUserSupported = isAnonymousUserSupported;
        roleService.createRole(UserRole.Admin);
    }
    @Override
    public AuthenticationStatus createUser(String userName, String password) throws NoSuchAlgorithmException {
        byte[] salt = saltService.getSalt();
        String saltedPassword = saltService.get_SHA_1_SecurePassword(password, salt);
        return userService.addUser(userName, saltedPassword, salt) ? AuthenticationStatus.Success : AuthenticationStatus.Failure_User_Already_Exists;
    }

    @Override
    public AuthenticationStatus deleteUser(String userName) {
        return userService.deleteUser(userName) ? AuthenticationStatus.Success: AuthenticationStatus.Failure_User_Does_Not_Exist;
    }

    @Override
    public AuthenticationStatus createRole(UserRole userRole) {
        if (userRole == UserRole.Admin)
            return AuthenticationStatus.Failure_User_Not_Allowed_To_Create_Admin_Role;
        return roleService.createRole(userRole) ? AuthenticationStatus.Success: AuthenticationStatus.Failure_Role_Already_Exists;
    }

    @Override
    public AuthenticationStatus deleteRole(UserRole userRole) {
        if (userRole == UserRole.Admin)
            return AuthenticationStatus.Failure_User_Not_Allowed_To_Delete_Admin_Role;
        return roleService.deleteRole(userRole) ? AuthenticationStatus.Success: AuthenticationStatus.Failure_Role_Does_Not_Exist;
    }

    @Override
    public AuthenticationStatus addRoleToUser(String userName, UserRole userRole){
        if (userRole == UserRole.Admin)
            return AuthenticationStatus.Failure_Cannot_Attach_Admin_Role_To_User;
        if (!userService.isUserPresent(userName))
            return AuthenticationStatus.Failure_User_Does_Not_Exist;
        User user = userService.getUser(userName);
        roleService.addRoleToUser(user, userRole);
        return AuthenticationStatus.Success;
    }

    @Override
    public AuthenticationToken authenticate(String userName, String password) throws Exception {
        if (userService.isUserPresent(userName) && userService.isUserSaltPresent(userName)){
            User user = userService.getUser(userName);
            byte[] salt = userService.getSalt(userName);
            String saltedPassword = saltService.get_SHA_1_SecurePassword(password, salt);
            if (user.getPassword().equals(saltedPassword)){
                if (!userService.isUserPresent(user.getUserName()))
                    throw new RuntimeException("User is not present in system , cannot authenticate");
                return authenticationService.getAuthenticationToken(user);
            }
        }
        throw new Exception("Failed to authenticate as user "+ userName+" not present");
    }

    @Override
    public AuthenticationToken authenticateAnonymous() throws Exception{
        if(!isAnonymousUserSupported)
            throw new Exception("Authentication token for anonymous user is not supported");
        return authenticationService.getAuthenticationToken(new User("Anonymous", "Anonymous"));
    }

    @Override
    public void invalidatePreExpiredToken(AuthenticationToken authenticationToken) throws Exception {
        authenticationService.invalidatePreExpiredToken(authenticationToken);
    }

    @Override
    public boolean checkRole(AuthenticationToken authenticationToken, UserRole role) throws Exception {
        errorCheck(authenticationToken);
        return roleService.getAllRoles(authenticationService.getUser(authenticationToken)).contains(role);
    }

    private void errorCheck(AuthenticationToken authenticationToken) throws Exception {
        if (!authenticationService.isAuthenticationTokenPresent(authenticationToken)) {
            throw new Exception("Authentication Token" + authenticationToken + " not present in system");
        }
    }

    @Override
    public List<UserRole> getAllRoles(AuthenticationToken authenticationToken) throws Exception {
        errorCheck(authenticationToken);
        return roleService.getAllRoles(authenticationService.getUser(authenticationToken));
    }

}
