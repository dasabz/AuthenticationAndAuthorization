package utils;

import java.util.Objects;
import java.util.UUID;

public class AuthenticationToken {
    private final String uniqueToken;
    private final User user;

    public AuthenticationToken(User user) {
        this.uniqueToken = user.getUserName() + UUID.randomUUID().toString();
        this.user = user;
    }

    public User getUser() {
        return user;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticationToken token = (AuthenticationToken) o;
        return Objects.equals(uniqueToken, token.uniqueToken) && Objects.equals(user, token.user);
    }

    @Override
    public int hashCode() {
        return Objects.hash(uniqueToken, user);
    }
}
