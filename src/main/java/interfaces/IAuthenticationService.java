package interfaces;

import exception.AuthenticationException;
import utils.AuthenticationToken;
import utils.User;
/*
    This microservice provides the authentication token and also helps in invalidating the token if needed
 */
public interface IAuthenticationService {
    AuthenticationToken getAuthenticationToken(User user) throws AuthenticationException;

    void invalidatePreExpiredToken(AuthenticationToken authenticationToken) throws AuthenticationException;
}
