package at.iteratec.meetup.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.filter.OncePerRequestFilter;
import sun.security.rsa.RSAPublicKeyImpl;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * This class intercepts calls to the backend and verifies if the request is authenticated. If so, an
 * {@link AbstractAuthenticationToken} is set so the security context.
 *
 * @author Herwig Steininger, herwig.steininger@iteratec.com
 */
public class MyAuthenticationFilter extends OncePerRequestFilter {

    /**
     * @see OncePerRequestFilter#doFilterInternal(HttpServletRequest, HttpServletResponse, FilterChain)
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        try {
            AbstractAuthenticationToken authToken = createAuthenticationToken(request);
            SecurityContextHolder.getContext().setAuthentication(authToken);
        } catch (Exception e) {
            // No valid JWT in request found
        }

        chain.doFilter(request, response);
    }

    /**
     * Based on the JWT received as a cookie in the {@link HttpServletRequest}, a validation of the JWT is triggered,
     * and if successful, a {@link User} is created and embedded into {@link MyAuthenticationToken} which in turn
     * will be set into the security context later on.
     *
     * @param request the {@link HttpServletRequest} containing the access and refresh token cookies
     * @return an {@link AbstractAuthenticationToken}, or {@code null} if no (valid) token was present
     */
    private AbstractAuthenticationToken createAuthenticationToken(HttpServletRequest request) throws Exception {
        String accessToken = getCookie("access", request).getValue();
        String refreshToken = getCookie("refresh", request).getValue();

        try {
            User user = getUserFromToken(accessToken);
            return new MyAuthenticationToken(user);
        } catch (ExpiredJwtException e) {
            // 1. Send refresh-token zu Keycloak to obtain a new access- and refresh-token (Post-Request)
            // 2. Store new tokens in cookies, overwritten previous cookie values
            // 3. Call createAuthenticationToken(...) again
        }

        throw new IllegalStateException();
    }

    /**
     * Utility method to obtain the cookie with the given name from the request.
     *
     * @param name    the cookie's name
     * @param request the {@link HttpServletRequest}
     * @return the {@link Cookie} if found, otherwise {@code null}
     */
    private Cookie getCookie(String name, HttpServletRequest request) {
        return Stream.of(request.getCookies())
                .filter(p -> p.getName().equals(name))
                .findFirst()
                .orElse(null);
    }

    /**
     * Checks the token's signature and extracts all relevant data (=claims) from the token to create
     * a {@link User} object such as username, roles...
     *
     * @param jwt the access token
     * @return {@link User}
     */
    private User getUserFromToken(String jwt) throws Exception {
        String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxypv78mZdiW4JxpFD7/6lspKTkSnBINKIPTdePUV1aYUC6are6Z9F2ovv2/GeDCf040viSVYt5H6YAChd+a6HcxHKGg8cWYRH6XGxvWFPlnH8uhecku/mSQIuC3yKbs/zxbL9p3BmNB3Wt44p+4B3tc8rkc0qV+D8BELp9rrQ8b2iOekNooVIt8YUfzC5IZZ/mS9nuaXpuUbYbW/GOygaJNl9f32N05v9hjAUwVRvisMsb+Zh5iYWaPsglNLGDPS/sx6KySe0RqRfGCSvYr5DQFVyyhuCmmTHGEL4wOD/TEYqLEyWiXS47Lnf6b6RPJD/re7x3ChIeYAWeCmPjJk1wIDAQAB";
        RSAPublicKey rsaPublicKey = new RSAPublicKeyImpl(Base64.getDecoder().decode(publicKey));

        Claims claims = Jwts.parser().setSigningKey(rsaPublicKey).parseClaimsJws(jwt).getBody();

        String username = (String) claims.get("preferred_username");

        List<SimpleGrantedAuthority> authorities = ((List<String>) claims.get("role", List.class))
                .stream()
                .map(p -> new SimpleGrantedAuthority(p))
                .collect(Collectors.toList());

        return new User(username, "", authorities);
    }
}