package services;

import utils.User;
import utils.AuthenticationStatus;
import utils.AuthenticationToken;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class AuthenticationService {
    private final ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();
    private final int preExpiryTime;
    private final TimeUnit timeUnit;
    private final Map<User, AuthenticationToken> userAuthenticationTokenMap = new HashMap<>();

    public AuthenticationService(int preExpiryTime, TimeUnit timeUnit) {
        this.preExpiryTime = preExpiryTime;
        this.timeUnit = timeUnit;
    }

    public User getUser(AuthenticationToken authenticationToken) {
        for(Map.Entry<User,AuthenticationToken> entry:userAuthenticationTokenMap.entrySet()){
            if (entry.getValue().equals(authenticationToken))
                return entry.getKey();
        }
        return null;
    }

    public AuthenticationToken getAuthenticationToken(User user) {
        if (!userAuthenticationTokenMap.containsKey(user)) {
            AuthenticationToken token = new AuthenticationToken(user.getUserName(), AuthenticationStatus.Success);
            userAuthenticationTokenMap.put(user, token);
            executor.schedule(() -> { userAuthenticationTokenMap.remove(user); }, preExpiryTime, timeUnit);
        }
        return userAuthenticationTokenMap.get(user);
    }

    public void invalidatePreExpiredToken(AuthenticationToken authenticationToken) throws Exception {
        if (!isAuthenticationTokenPresent(authenticationToken)) {
            throw new Exception("Authentication Token" + authenticationToken + " not present in system, cannot invalidate");
        }
        userAuthenticationTokenMap.values().remove(authenticationToken);
    }

    public boolean isAuthenticationTokenPresent(AuthenticationToken authenticationToken) {
        return userAuthenticationTokenMap.containsValue(authenticationToken);
    }


}
