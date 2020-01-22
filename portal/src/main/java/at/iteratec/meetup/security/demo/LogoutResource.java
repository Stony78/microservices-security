package at.iteratec.meetup.security.demo;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.util.stream.Stream;

/**
 * Resource class offering a method to log out.
 *
 * @author Herwig Steininger, herwig.steininger@iteratec.com
 */
@RestController
public class LogoutResource {
    /**
     * ReST endpoint deleting the user's JWTs and Keycloak session in order to enforce a logout.
     *
     * @param principal {@link Principal}
     * @param response  {@link HttpServletResponse} for the cookie handling
     * @return {@link ResponseEntity} describing the outcome of the logout
     */
    @RequestMapping(path = "/api/logout", method = RequestMethod.GET)
    public ResponseEntity<String> logout(Principal principal, HttpServletResponse response) {
        // Delete the cookies containing the access and refresh tokens
        Stream.of("access", "refresh").forEach(cookieName -> {
            Cookie cookie = new Cookie(cookieName, null);
            cookie.setMaxAge(0);
            response.addCookie(cookie);
        });

        // Let the admin kill the current user's keycloak session
        Keycloak keycloak = KeycloakBuilder.builder()
                .serverUrl("http://localhost:8080/auth")
                .username("admin")
                .password("admin")
                .realm("master")
                .clientId("demo")
                .build();
        String id = keycloak.realm("master").users().search(principal.getName()).get(0).getId();
        keycloak.realm("master").users().get(id).logout();

        return ResponseEntity.ok("Goodbye");
    }
}