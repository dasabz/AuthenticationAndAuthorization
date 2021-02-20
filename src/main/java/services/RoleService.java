package services;

import utils.User;
import utils.UserRole;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class RoleService implements interfaces.IRoleService {
    private final Map<User, List<UserRole>> userRoleMappingCache = new HashMap<>();
    private final List<UserRole> userRoles = new ArrayList<>();

    public RoleService() {
    }

    @Override
    public boolean createRole(UserRole userRole) {
        if (!userRoles.contains(userRole)) {
            userRoles.add(userRole);
            return true;
        }
        return false;
    }

    @Override
    public boolean deleteRole(UserRole userRole) {
        if (userRoles.contains(userRole)) {
            userRoles.remove(userRole);
            return true;
        }
        return false;
    }

    @Override
    public void addRoleToUser(User user, UserRole userRole) {
        if (!userRoleMappingCache.containsKey(user)) {
            List<UserRole> userRoles = new ArrayList<>();
            userRoles.add(userRole);
            userRoleMappingCache.put(user, userRoles);
        } else {
            userRoleMappingCache.get(user).add(userRole);
        }
    }

    @Override
    public List<UserRole> getAllRoles(User user) {
        return userRoleMappingCache.get(user);
    }
}
