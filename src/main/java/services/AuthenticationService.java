package services;

import exception.AuthenticationException;
import utils.AuthenticationToken;
import utils.User;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class AuthenticationService implements interfaces.IAuthenticationService {
    private final ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();
    private final int preExpiryTime;
    private final TimeUnit timeUnit;
    private final Map<User, AuthenticationToken> userAuthenticationTokenMap = new HashMap<>();

    public AuthenticationService(int preExpiryTime, TimeUnit timeUnit) {
        this.preExpiryTime = preExpiryTime;
        this.timeUnit = timeUnit;
    }

    @Override
    public AuthenticationToken getAuthenticationToken(User user) throws AuthenticationException {
        if (user.getIsTokenExpired()){
            user.setIsTokenExpired(false);
            throw new AuthenticationException("Authentication token has expired for user " + user);
        }
        if (!userAuthenticationTokenMap.containsKey(user)) {
            AuthenticationToken token = new AuthenticationToken(user);
            userAuthenticationTokenMap.put(user, token);
            executor.schedule(() -> {
                user.setIsTokenExpired(true);
                userAuthenticationTokenMap.remove(user);
            }, preExpiryTime, timeUnit);
        }
        return userAuthenticationTokenMap.get(user);
    }

    @Override
    public void invalidatePreExpiredToken(AuthenticationToken authenticationToken) throws AuthenticationException {
        if (!userAuthenticationTokenMap.containsValue(authenticationToken)) {
            throw new AuthenticationException("Authentication Token" + authenticationToken + " not present in system, cannot invalidate");
        }
        userAuthenticationTokenMap.values().remove(authenticationToken);
    }
}
