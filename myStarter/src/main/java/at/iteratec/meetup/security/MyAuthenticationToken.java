package at.iteratec.meetup.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;

/**
 * After a successful authentication, an instance of {@link AbstractAuthenticationToken} needs to be created,
 * encapsulating the current {@link User} with his roles. This token has to be placed in the security context.
 *
 * @author Herwig Steininger, herwig.steininger@iteratec.com
 */
public class MyAuthenticationToken extends AbstractAuthenticationToken {
    public MyAuthenticationToken(User user) {
        super(user.getAuthorities());
        setDetails(user);
        setAuthenticated(true);
    }

    /**
     * @see Authentication#getPrincipal()
     */
    @Override
    public Object getPrincipal() {
        return getDetails();
    }

    /**
     * @see Authentication#getCredentials()
     */
    @Override
    public Object getCredentials() {
        return null;
    }
}