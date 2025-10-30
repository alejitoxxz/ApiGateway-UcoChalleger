package co.edu.uco.apigatewayservice.filter;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

@Component
public class TokenRelayGlobalFilter implements GlobalFilter, Ordered {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return exchange.getPrincipal()
                .filter(Authentication.class::isInstance)
                .cast(Authentication.class)
                .map(this::resolveTokenValue)
                .filter(token -> token != null && !token.isBlank())
                .flatMap(token -> {
                    ServerWebExchange mutatedExchange = exchange.mutate()
                            .request(builder -> builder.headers(headers -> headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + token)))
                            .build();
                    return chain.filter(mutatedExchange);
                })
                .switchIfEmpty(chain.filter(exchange));
    }

    private String resolveTokenValue(Authentication authentication) {
        if (authentication instanceof AbstractOAuth2TokenAuthenticationToken<?> tokenAuthentication) {
            return tokenAuthentication.getToken().getTokenValue();
        }
        Object credentials = authentication.getCredentials();
        if (credentials instanceof AbstractOAuth2Token token) {
            return token.getTokenValue();
        }
        return null;
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 20;
    }
}
