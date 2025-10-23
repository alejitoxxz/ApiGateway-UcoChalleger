package co.edu.uco.apigatwayservice.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class SecurityConfig {

    // Claim de roles con namespace (Auth0)
    private static final String ROLES_CLAIM = "https://uco-challenge/roles";
    private static final String ADMIN_ROLE = "administrador";
    private static final String USER_ROLE  = "usuario";

    @Value("${auth0.audience}")
    private String audience;

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuer;

    @Value("${web.cors.allowed-origins}")
    private String corsAllowedOrigins;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .authorizeExchange(exchange -> exchange
                .pathMatchers("/api/public/**").permitAll()
                .pathMatchers("/api/admin/**").hasAuthority(ADMIN_ROLE)
                .pathMatchers("/api/user/**").hasAnyAuthority(ADMIN_ROLE, USER_ROLE)
                // .pathMatchers("/actuator/**").permitAll() // si lo necesitas
                .anyExchange().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .jwtDecoder(jwtDecoder()) // <- ahora es ReactiveJwtDecoder
                    .jwtAuthenticationConverter(jwtAuthenticationConverter())
                )
            )
            .build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(parseAllowedOrigins());
        config.setAllowedMethods(List.of("GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS", "HEAD"));
        config.setAllowCredentials(true);
        // Acepta cualquier header (útil cuando Auth0 agrega varios)
        config.setAllowedHeaders(List.of("*"));
        config.setExposedHeaders(List.of("X-Get-Header"));
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    private List<String> parseAllowedOrigins() {
        if (corsAllowedOrigins == null || corsAllowedOrigins.isBlank()) {
            return List.of();
        }
        return Arrays.stream(corsAllowedOrigins.split(","))
            .map(String::trim)
            .filter(origin -> !origin.isBlank())
            .collect(Collectors.toList());
    }

    /**
     * ReactiveJwtDecoder: envolvemos NimbusJwtDecoder en un Mono para WebFlux.
     * Así podemos mantener las validaciones personalizadas (issuer + audience).
     */
    @Bean
    public org.springframework.security.oauth2.jwt.ReactiveJwtDecoder jwtDecoder() {
        NimbusJwtDecoder nimbus = (NimbusJwtDecoder) JwtDecoders.fromOidcIssuerLocation(issuer);

        OAuth2TokenValidator<Jwt> withIssuer   = JwtValidators.createDefaultWithIssuer(issuer);
        OAuth2TokenValidator<Jwt> withAudience = new DelegatingOAuth2TokenValidator<>(withIssuer, new AudienceValidator(audience));
        nimbus.setJwtValidator(withAudience);

        // Adaptación manual a ReactiveJwtDecoder
        return token -> Mono.fromCallable(() -> nimbus.decode(token));
    }

    /**
     * Convierte el claim de roles (namespace) en authorities sin prefijo "ROLE_".
     * Permite usar hasAuthority("administrador") / "usuario".
     */
    @Bean
    public Converter<Jwt, Mono<AbstractAuthenticationToken>> jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthoritiesClaimName(ROLES_CLAIM);
        authoritiesConverter.setAuthorityPrefix(""); // sin "ROLE_"

        JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
        jwtConverter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);

        return new ReactiveJwtAuthenticationConverterAdapter(jwtConverter);
    }
}
