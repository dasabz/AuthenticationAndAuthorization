package interfaces;

import utils.User;
import utils.UserRole;

import java.util.List;

public interface IRoleService {
    boolean createRole(UserRole userRole);

    boolean deleteRole(UserRole userRole);

    void addRoleToUser(User user, UserRole userRole);

    List<UserRole> getAllRoles(User user);
}
