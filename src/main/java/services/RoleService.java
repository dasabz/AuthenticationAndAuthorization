package services;

import exception.AuthenticationException;
import exception.RoleAlreadyExistsException;
import exception.RoleDoesNotExistException;
import utils.AuthenticationToken;
import utils.Role;
import utils.User;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class RoleService implements interfaces.IRoleService {
    private final AuthenticationService authenticationService;
    private final Map<User, List<Role>> userRoleMappingCache = new HashMap<>();
    private final List<Role> roles = new ArrayList<>();

    public RoleService(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @Override
    public void createRole(Role role) throws RoleAlreadyExistsException {
        if (roles.contains(role)) {
            throw new RoleAlreadyExistsException("Role "+ role + " already exists");
        }
        roles.add(role);
    }

    @Override
    public void deleteRole(Role role) throws RoleDoesNotExistException {
        if (!roles.remove(role))
            throw new RoleDoesNotExistException("Role "+ role +" does not exist");
    }

    @Override
    public void addRoleToUser(User user, Role role) throws AuthenticationException {
        AuthenticationToken authenticationToken = authenticationService.getAuthenticationToken(user);
        if (authenticationToken == null)
            throw new AuthenticationException("Failed to authenticate user"+ user + " and thus cannot add roles to user");

        if (!userRoleMappingCache.containsKey(user)) {
            List<Role> roles = new ArrayList<>();
            roles.add(role);
            userRoleMappingCache.put(user, roles);
        } else {
            userRoleMappingCache.get(user).add(role);
        }
    }


    @Override
    public List<Role> getAllRoles(User user) throws AuthenticationException {
        AuthenticationToken authenticationToken = authenticationService.getAuthenticationToken(user);
        if (authenticationToken != null) {
            return userRoleMappingCache.get(user);
        }
        throw new AuthenticationException("Failed to authenticate user"+ user + " and thus cannot get roles pertaining to user");
    }

    @Override
    public boolean checkRole(User user, Role role) throws AuthenticationException {
        AuthenticationToken authenticationToken = authenticationService.getAuthenticationToken(user);
        if(authenticationToken != null) {
            return getAllRoles(user).contains(role);
        }
        throw new AuthenticationException("Failed to authenticate user"+ user + " and thus cannot check role for the user");
    }

    @Override
    public boolean containsRole(Role role) {
        return roles.contains(role);
    }
}
