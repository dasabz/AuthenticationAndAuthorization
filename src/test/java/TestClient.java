import authentication.AuthenticationManagerFacade;
import org.junit.Assert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import services.AuthenticationService;
import services.RoleService;
import services.SaltService;
import services.UserService;
import utils.AuthenticationStatus;
import utils.AuthenticationToken;
import utils.UserRole;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;


class TestClient {
    private final int preExpiryTime = 5;
    private final AuthenticationManagerFacade authenticationManagerFacade = new AuthenticationManagerFacade(
            new UserService(),
            new RoleService(),
            new SaltService(),
            new AuthenticationService(preExpiryTime, TimeUnit.SECONDS),
            false
    );

    @Test
    public void createUser() throws NoSuchAlgorithmException {
        Assert.assertEquals(AuthenticationStatus.Success, authenticationManagerFacade.createUser("Client1", "Password1"));
        Assert.assertEquals(AuthenticationStatus.Failure_User_Already_Exists, authenticationManagerFacade.createUser("Client1", "Password1"));

        Assert.assertEquals(AuthenticationStatus.Success, authenticationManagerFacade.createUser("Client2", "Password2"));
        Assert.assertEquals(AuthenticationStatus.Failure_User_Already_Exists, authenticationManagerFacade.createUser("Client2", "Password2"));
    }

    @Test
    public void deleteUser() throws NoSuchAlgorithmException {
        Assert.assertEquals(AuthenticationStatus.Success, authenticationManagerFacade.createUser("Client1", "Password1"));
        Assert.assertEquals(AuthenticationStatus.Success, authenticationManagerFacade.deleteUser("Client1"));
        Assert.assertEquals(AuthenticationStatus.Failure_User_Does_Not_Exist, authenticationManagerFacade.deleteUser("Client1"));
    }

    @Test
    public void createRole() {
        Assert.assertEquals(AuthenticationStatus.Failure_User_Not_Allowed_To_Create_Admin_Role, authenticationManagerFacade.createRole(UserRole.Admin));
        Assert.assertEquals(AuthenticationStatus.Success, authenticationManagerFacade.createRole(UserRole.NormalUser));
        Assert.assertEquals(AuthenticationStatus.Failure_Role_Already_Exists, authenticationManagerFacade.createRole(UserRole.NormalUser));
    }

    @Test
    public void deleteRole() {
        Assert.assertEquals(AuthenticationStatus.Failure_User_Not_Allowed_To_Delete_Admin_Role, authenticationManagerFacade.deleteRole(UserRole.Admin));
        Assert.assertEquals(AuthenticationStatus.Success, authenticationManagerFacade.createRole(UserRole.NormalUser));
        Assert.assertEquals(AuthenticationStatus.Success, authenticationManagerFacade.deleteRole(UserRole.NormalUser));

        Assert.assertEquals(AuthenticationStatus.Failure_Role_Does_Not_Exist, authenticationManagerFacade.deleteRole(UserRole.NormalUser));
    }

    @Test
    public void addRoleToUser() throws NoSuchAlgorithmException {
        Assert.assertEquals(AuthenticationStatus.Failure_User_Does_Not_Exist, authenticationManagerFacade.addRoleToUser("Client1", UserRole.NormalUser));
        Assert.assertEquals(AuthenticationStatus.Success, authenticationManagerFacade.createUser("Client1", "Password1"));
        Assert.assertEquals(AuthenticationStatus.Success, authenticationManagerFacade.addRoleToUser("Client1", UserRole.NormalUser));
        Assert.assertEquals(AuthenticationStatus.Failure_Cannot_Attach_Admin_Role_To_User, authenticationManagerFacade.addRoleToUser("Client1", UserRole.Admin));
    }

    @Test
    public void authenticate() throws Exception {
        Assertions.assertThrows(Exception.class, () -> authenticationManagerFacade.authenticate("Client1", "Password1"));
        Assert.assertEquals(AuthenticationStatus.Success, authenticationManagerFacade.createUser("Client1", "Password1"));
        Assert.assertNotNull(authenticationManagerFacade.authenticate("Client1", "Password1"));
    }

    @Test
    public void authenticateAnonymous() throws Exception {
        Assertions.assertThrows(Exception.class, authenticationManagerFacade::authenticateAnonymous);
        AuthenticationManagerFacade authenticationManagerFacade = new AuthenticationManagerFacade(
                new UserService(),
                new RoleService(),
                new SaltService(),
                new AuthenticationService(preExpiryTime, TimeUnit.SECONDS),
                true
        );
        Assert.assertNotNull(authenticationManagerFacade.authenticateAnonymous());
    }

    @Test
    public void invalidatePreExpiredToken() throws Exception {
        Assert.assertEquals(AuthenticationStatus.Success, authenticationManagerFacade.createUser("Client1", "Password1"));
        AuthenticationToken token = authenticationManagerFacade.authenticate("Client1", "Password1");
        authenticationManagerFacade.invalidatePreExpiredToken(token);
    }

    @Test
    public void checkRole() throws Exception {
        Assert.assertEquals(AuthenticationStatus.Success, authenticationManagerFacade.createUser("Client1", "Password1"));
        AuthenticationToken token = authenticationManagerFacade.authenticate("Client1", "Password1");
        Assert.assertEquals(AuthenticationStatus.Success, authenticationManagerFacade.addRoleToUser("Client1", UserRole.NormalUser));
        Assert.assertTrue(authenticationManagerFacade.checkRole(token, UserRole.NormalUser));
    }

    @Test
    public void getAllRoles() throws Exception {
        Assert.assertEquals(AuthenticationStatus.Success, authenticationManagerFacade.createUser("Client1", "Password1"));
        AuthenticationToken token = authenticationManagerFacade.authenticate("Client1", "Password1");
        Assert.assertEquals(AuthenticationStatus.Success, authenticationManagerFacade.addRoleToUser("Client1", UserRole.NormalUser));
        Assert.assertEquals(AuthenticationStatus.Success, authenticationManagerFacade.addRoleToUser("Client1", UserRole.PrivilegedUser));
        Assert.assertEquals(Arrays.asList(UserRole.NormalUser, UserRole.PrivilegedUser), authenticationManagerFacade.getAllRoles(token));

        Thread.sleep(preExpiryTime * 1000);
        Assertions.assertThrows(Exception.class, () -> authenticationManagerFacade.getAllRoles(token));
    }
}

