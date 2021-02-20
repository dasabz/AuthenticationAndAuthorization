import authentication.AuthenticationManagerFacade;
import exception.*;
import org.junit.Assert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import services.AuthenticationService;
import services.RoleService;
import services.SaltService;
import services.UserService;
import utils.AuthenticationToken;
import utils.Role;
import utils.User;

import java.util.Arrays;
import java.util.concurrent.TimeUnit;

class TestClient {
    private static final SaltService saltService = Mockito.mock(SaltService.class);
    private final int preExpiryTime = 2;
    AuthenticationService authenticationService = new AuthenticationService(preExpiryTime, TimeUnit.MILLISECONDS);
    RoleService roleService = new RoleService(authenticationService);
    UserService userService = new UserService(authenticationService, saltService);
    User user = new User("User1", "Password1");
    User expectedUser = new User("User1", "MockPassword1");

    private final AuthenticationManagerFacade authenticationManagerFacade = new AuthenticationManagerFacade(
            userService,
            roleService,
            saltService,
            authenticationService,
            false
    );

    @BeforeAll
    public static void init() {
        byte[] dummy = new byte[]{1, 2, 3};
        Mockito.when(saltService.getSalt()).thenReturn(dummy);
        Mockito.when(saltService.get_SHA_1_SecurePassword("Password1", dummy)).thenReturn("MockPassword1");
        Mockito.when(saltService.get_SHA_1_SecurePassword("Password2", dummy)).thenReturn("MockPassword2");
    }

    @Test
    public void testCreateUser() throws UserAlreadyExistsException {
        User expectedUser = new User("User1", "MockPassword1");
        Assert.assertEquals(expectedUser, authenticationManagerFacade.createUser("User1", "Password1"));
        Assertions.assertThrows(UserAlreadyExistsException.class, () -> authenticationManagerFacade.createUser("User1", "Password1"));

        //Another user can have the same username as user1 but a different password, even he should be allowed
        User expectedUserWithSameUserName = new User("User1", "MockPassword2");
        Assert.assertEquals(expectedUserWithSameUserName, authenticationManagerFacade.createUser("User1", "Password2"));
    }

    @Test
    public void testDeleteUser() throws UserAlreadyExistsException, UserDoesntExistException {
        User expectedUser = new User("User1", "MockPassword1");
        Assert.assertEquals(expectedUser, authenticationManagerFacade.createUser("User1", "Password1"));

        authenticationManagerFacade.deleteUser(expectedUser);
        Assert.assertFalse(authenticationManagerFacade.containsUser(expectedUser));
        Assertions.assertThrows(UserDoesntExistException.class, () -> authenticationManagerFacade.deleteUser(expectedUser));
    }

    @Test
    public void testCreateRole() throws RoleAlreadyExistsException {
        authenticationManagerFacade.createRole(Role.NormalUser);
        Assert.assertTrue(authenticationManagerFacade.containsRole(Role.NormalUser));
        Assertions.assertThrows(RoleAlreadyExistsException.class, () -> authenticationManagerFacade.createRole(Role.NormalUser));
        authenticationManagerFacade.createRole(Role.PrivilegedUser);
        Assert.assertTrue(authenticationManagerFacade.containsRole(Role.PrivilegedUser));
    }

    @Test
    public void testDeleteRole() throws RoleAlreadyExistsException, RoleDoesNotExistException {
        authenticationManagerFacade.createRole(Role.NormalUser);
        Assert.assertTrue(authenticationManagerFacade.containsRole(Role.NormalUser));
        authenticationManagerFacade.deleteRole(Role.NormalUser);
        Assert.assertFalse(authenticationManagerFacade.containsRole(Role.NormalUser));
        Assertions.assertThrows(RoleDoesNotExistException.class, () -> authenticationManagerFacade.deleteRole(Role.NormalUser));
        Assertions.assertThrows(RoleDoesNotExistException.class, () -> authenticationManagerFacade.deleteRole(Role.PrivilegedUser));
    }

    @Test
    public void testAddRoleToUser() throws AuthenticationException, UserAlreadyExistsException, RoleAlreadyExistsException {
        User user = new User("User1", "Password1");
        User expectedUser = new User("User1", "MockPassword1");
        Assertions.assertThrows(AuthenticationException.class, () -> authenticationManagerFacade.addRoleToUser(user, Role.NormalUser));
        Assert.assertEquals(expectedUser, authenticationManagerFacade.createUser("User1", "Password1"));
        authenticationManagerFacade.createRole(Role.NormalUser);
        authenticationManagerFacade.addRoleToUser(user, Role.NormalUser);
        authenticationManagerFacade.addRoleToUser(user, Role.PrivilegedUser);
        Assert.assertTrue(authenticationManagerFacade.checkRole(user, Role.NormalUser));
        Assert.assertEquals(Arrays.asList(Role.NormalUser, Role.PrivilegedUser), authenticationManagerFacade.getAllRoles(user));
    }

    @Test
    public void testAuthenticate() throws Exception {
        Assertions.assertThrows(AuthenticationException.class, () -> authenticationManagerFacade.authenticate("Client1", "Password1"));
        authenticationManagerFacade.createUser("Client1", "Password1");
        Assert.assertNotNull(authenticationManagerFacade.authenticate("Client1", "Password1"));
    }

    @Test
    public void testAuthenticateAnonymous() throws Exception {
        Assertions.assertThrows(AuthenticationException.class, authenticationManagerFacade::authenticateAnonymous);
        AuthenticationManagerFacade authenticationManagerFacade = new AuthenticationManagerFacade(
                userService,
                roleService,
                new SaltService(),
                authenticationService,
                true
        );
        Assert.assertNotNull(authenticationManagerFacade.authenticateAnonymous());
    }

    @Test
    public void testInvalidatePreExpiredToken() throws Exception {
        authenticationManagerFacade.createUser("Client1", "Password1");
        AuthenticationToken token = authenticationManagerFacade.authenticate("Client1", "Password1");
        Assert.assertNotNull(token);
        authenticationManagerFacade.invalidatePreExpiredToken(token);
        Assertions.assertThrows(AuthenticationException.class, () -> authenticationManagerFacade.addRoleToUser(expectedUser, Role.NormalUser));
    }

    @Test
    public void testCheckRoleForUser() throws AuthenticationException, UserAlreadyExistsException, RoleAlreadyExistsException, InterruptedException {
        Assertions.assertThrows(AuthenticationException.class, () -> authenticationManagerFacade.addRoleToUser(user, Role.NormalUser));
        Assert.assertEquals(expectedUser, authenticationManagerFacade.createUser("User1", "Password1"));
        authenticationManagerFacade.createRole(Role.NormalUser);
        authenticationManagerFacade.addRoleToUser(user, Role.NormalUser);
        Assert.assertTrue(authenticationManagerFacade.checkRole(user, Role.NormalUser));
    }

    @Test
    public void testGetAllRoles() throws Exception, RoleAlreadyExistsException {
        Assert.assertEquals(expectedUser, authenticationManagerFacade.createUser("User1", "Password1"));
        authenticationManagerFacade.createRole(Role.NormalUser);

        authenticationManagerFacade.addRoleToUser(user, Role.NormalUser);
        authenticationManagerFacade.addRoleToUser(user, Role.PrivilegedUser);
        Assert.assertTrue(authenticationManagerFacade.checkRole(user, Role.NormalUser));

        Thread.sleep(preExpiryTime +1); // time offset as time may not be exactly in sync across junit thread and executor thread causing flakiness
        //Trying after token has expired gives an exception that authentication has expired.
        Assertions.assertThrows(AuthenticationException.class, () -> authenticationManagerFacade.getAllRoles(user));
        //On trying again it re-authenticates and thus can verify the roles correctly
        Assert.assertTrue(authenticationManagerFacade.checkRole(user, Role.NormalUser));
    }
}

