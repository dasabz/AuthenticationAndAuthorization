package utils;

import java.util.Objects;
import java.util.UUID;

public class AuthenticationToken {
    String uniqueToken;
    AuthenticationStatus authenticationStatus;
    public AuthenticationToken(String userName, AuthenticationStatus authenticationStatus) {
        this.uniqueToken = userName + UUID.randomUUID().toString();
        this.authenticationStatus = authenticationStatus;
    }

    public AuthenticationStatus getResultStatus() {
        return authenticationStatus;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticationToken token = (AuthenticationToken) o;
        return Objects.equals(uniqueToken, token.uniqueToken) &&
                authenticationStatus == token.authenticationStatus;
    }

    @Override
    public int hashCode() {
        return Objects.hash(uniqueToken, authenticationStatus);
    }
}
