package authentication;

import exception.*;
import interfaces.*;
import utils.User;
import utils.AuthenticationToken;
import utils.Role;

import java.util.List;

public class AuthenticationManagerFacade implements IAuthenticationManagerFacade {
    private final IUserService           userService;
    private final IRoleService           roleService;
    private final IAuthenticationService authenticationService;
    private final boolean                isAnonymousUserSupported ;
    public AuthenticationManagerFacade(IUserService userService, IRoleService roleService, ISaltService saltService, IAuthenticationService authenticationService, boolean isAnonymousUserSupported){
        this.userService              = userService;
        this.roleService              = roleService;
        this.authenticationService    = authenticationService;
        this.isAnonymousUserSupported = isAnonymousUserSupported;
    }
    @Override
    public User createUser(String userName, String password) throws UserAlreadyExistsException {
        return userService.addUser(userName, password);
    }

    @Override
    public void deleteUser(User user) throws UserDoesntExistException {
        userService.deleteUser(user);
    }

    @Override
    public void createRole(Role role) throws RoleAlreadyExistsException {
        roleService.createRole(role);
    }

    @Override
    public void deleteRole(Role role) throws RoleDoesNotExistException {
        roleService.deleteRole(role);
    }

    @Override
    public void addRoleToUser(User user, Role role) throws AuthenticationException {
        if (userService.authenticate(user.getUserName(), user.getPassword()) != null)
            roleService.addRoleToUser(user, role);
    }

    @Override
    public AuthenticationToken authenticate(String userName, String password) throws AuthenticationException {
        return userService.authenticate(userName, password);
    }

    @Override
    public AuthenticationToken authenticateAnonymous() throws AuthenticationException{
        if(!isAnonymousUserSupported)
            throw new AuthenticationException("Authentication token for anonymous user is not supported");
        return authenticationService.getAuthenticationToken(new User("Anonymous", "Anonymous"));
    }

    @Override
    public void invalidatePreExpiredToken(AuthenticationToken authenticationToken) throws AuthenticationException {
        authenticationService.invalidatePreExpiredToken(authenticationToken);
    }

    @Override
    public boolean checkRole(User user, Role role) throws AuthenticationException {
        return roleService.checkRole(user, role);
    }

    @Override
    public List<Role> getAllRoles(User user) throws AuthenticationException {
        return roleService.getAllRoles(user);
    }

    @Override
    public boolean containsUser(User user) {
        return userService.containsUser(user);
    }

    @Override
    public boolean containsRole(Role role) {
        return roleService.containsRole(role);
    }
}
