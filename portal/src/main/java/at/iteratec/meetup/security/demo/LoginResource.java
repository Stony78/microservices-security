package at.iteratec.meetup.security.demo;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.token.TokenManager;
import org.keycloak.representations.AccessTokenResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.NotAuthorizedException;

/**
 * Resource class offering a method to authenticated against Keycloak.
 *
 * @author Herwig Steininger, herwig.steininger@iteratec.com
 */
@RestController
public class LoginResource {
    /**
     * ReST endpoint taking username and password to authenticate against Keycloak.
     * If the login was successful, the JWTs received, will be returned in cookies.
     *
     * @param username the user's username
     * @param password the user's password
     * @param response {@link HttpServletResponse} for the cookie handling
     * @return {@link ResponseEntity} describing the outcome of the login attempt
     */
    @RequestMapping(path = "/api/login", method = RequestMethod.GET)
    public ResponseEntity<String> login(@RequestParam String username,
                                        @RequestParam String password,
                                        HttpServletResponse response) {
        Keycloak keycloak = KeycloakBuilder.builder()
                .serverUrl("http://localhost:8080/auth")
                .username(username)
                .password(password)
                .realm("master")
                .clientId("demo")
                .build();

        TokenManager tokenManager = keycloak.tokenManager();

        try {
            AccessTokenResponse tokenResponse = tokenManager.getAccessToken();
            response.addCookie(new Cookie("access", tokenResponse.getToken()));
            response.addCookie(new Cookie("refresh", tokenResponse.getRefreshToken()));
        } catch (NotAuthorizedException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Failed");
        }

        return ResponseEntity.ok("Success");
    }
}