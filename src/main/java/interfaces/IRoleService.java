package interfaces;

import exception.AuthenticationException;
import exception.RoleAlreadyExistsException;
import exception.RoleDoesNotExistException;
import utils.User;
import utils.Role;

import java.util.List;
/*
    This microservice helps in creating role , delete role for which it does not need authentication.
    However in order to actually do an operation like addingRoleToAUser or to check for roles for a user ,
    the user needs to be authenticated first
 */
public interface IRoleService {
    void createRole(Role role) throws RoleAlreadyExistsException;

    void deleteRole(Role role) throws RoleDoesNotExistException;

    void addRoleToUser(User user, Role role) throws AuthenticationException;

    List<Role> getAllRoles(User user) throws AuthenticationException;

    boolean checkRole(User user, Role role) throws AuthenticationException;

    boolean containsRole(Role role);
}
