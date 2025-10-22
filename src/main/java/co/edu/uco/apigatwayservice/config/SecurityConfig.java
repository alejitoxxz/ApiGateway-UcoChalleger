package co.edu.uco.apigatwayservice.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

  @Value("${auth0.audience}")
  private String audience;

  @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
  private String issuer;

  @Bean
  public ReactiveJwtDecoder jwtDecoder() {
    NimbusReactiveJwtDecoder decoder =
        (NimbusReactiveJwtDecoder) ReactiveJwtDecoders.fromIssuerLocation(issuer);

    OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuer);
    OAuth2TokenValidator<Jwt> withAudience = token ->
        token.getAudience() != null && token.getAudience().contains(audience)
          ? OAuth2TokenValidatorResult.success()
          : OAuth2TokenValidatorResult.failure(
              new OAuth2Error("invalid_token", "Invalid audience", null));

    decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(withIssuer, withAudience));
    return decoder;
  }

  private ReactiveJwtAuthenticationConverterAdapter jwtAuthConverter() {
    var converter = new JwtAuthenticationConverter();
    converter.setJwtGrantedAuthoritiesConverter(jwt -> {
      // "scope": "a b c"
      var scopeClaim = (String) jwt.getClaims().getOrDefault("scope", "");
      var scopes = scopeClaim.isBlank() ? Set.<String>of() : Set.of(scopeClaim.split(" "));

      // "permissions": ["x","y"]
      var permsObj = jwt.getClaims().get("permissions");
      var perms = permsObj instanceof Collection<?> c
          ? c.stream().map(Object::toString).collect(Collectors.toSet())
          : Set.<String>of();

      var all = new HashSet<String>();
      all.addAll(scopes);
      all.addAll(perms);

      return all.stream()
          .map(s -> (org.springframework.security.core.GrantedAuthority) () -> "SCOPE_" + s)
          .collect(Collectors.toSet());
    });
    return new ReactiveJwtAuthenticationConverterAdapter(converter);
  }

  private Mono<AuthorizationDecision> hasAnyScope(
      org.springframework.security.core.Authentication a, String... scopes) {
    var needed = Set.of(scopes);
    boolean ok = a.getAuthorities().stream().anyMatch(ga ->
        needed.contains(ga.getAuthority().replaceFirst("^SCOPE_", ""))
    );
    return Mono.just(new AuthorizationDecision(ok));
  }

  @Bean
  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
    http.csrf(ServerHttpSecurity.CsrfSpec::disable);

    http.authorizeExchange(auth -> auth
        .pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()
        .pathMatchers("/actuator/health", "/actuator/info").permitAll()

        // Solo admin (porque solo el admin tiene estos permisos en Auth0)
        .pathMatchers("/users/**").access((authz, ctx) ->
            authz.flatMap(a -> hasAnyScope(a, "users:read", "users:write", "admin:access"))
        )

        .anyExchange().authenticated()
    );

    http.oauth2ResourceServer(oauth -> oauth
        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthConverter()))
    );

    return http.build();
  }
}
