package at.iteratec.meetup.security.demo;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/**
 * Demo resource offering two ReST endpoints for demonstration purposes.
 *
 * @author Herwig Steininger, herwig.steininger@iteratec.com
 */
@RestController
public class DemoResource {
    /**
     * Delivers the name of the authenticated user.
     *
     * @param principal {@link Principal}
     * @return {@link ResponseEntity}
     */
    @RequestMapping(path = "/api/demo1", method = RequestMethod.GET)
    public ResponseEntity<String> demo1(Principal principal) {
        return ResponseEntity.ok("Hello " + principal.getName() + ", since you're AUTHENTICATED you can read this!");
    }

    /**
     * Delivers the name of the authenticated user if he has the role "mastermind".
     *
     * @param principal {@link Principal}
     * @return {@link ResponseEntity}
     */
    @RequestMapping(path = "/api/demo2", method = RequestMethod.GET)
    @PreAuthorize("hasAuthority('mastermind')")
    public ResponseEntity<String> demo2(Principal principal) {
        return ResponseEntity.ok("Hello " + principal.getName() + ", since you're the MASTERMIND you can read this!");
    }
}