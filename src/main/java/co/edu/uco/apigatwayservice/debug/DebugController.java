package co.edu.uco.apigatwayservice.debug;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.*;

@RestController
@RequestMapping("/debug")
public class DebugController {

  @GetMapping("/whoami")
  public Mono<Map<String, Object>> whoami(@AuthenticationPrincipal Jwt jwt, Authentication auth) {
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("authenticated", auth != null && auth.isAuthenticated());
    out.put("name", auth != null ? auth.getName() : null);
    out.put("authorities", auth != null ? auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList() : List.of());
    out.put("roles_claim", jwt != null ? jwt.getClaimAsStringList("https://uco-challenge/roles") : List.of());
    out.put("aud", jwt != null ? jwt.getAudience() : List.of());
    out.put("iss", jwt != null ? String.valueOf(jwt.getIssuer()) : null);
    return Mono.just(out);
  }
}

