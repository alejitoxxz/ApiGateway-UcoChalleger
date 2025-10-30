package co.edu.uco.ucochallenge.filter;

import org.springframework.core.Ordered;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;

@Component
public class InternalSignatureFilter implements GlobalFilter, Ordered {

    private static final String INTERNAL_SIGNATURE_HEADER = "X-Internal-Signature";

    private final String signature;

    public InternalSignatureFilter(Environment environment) {
        this.signature = environment.getProperty("gateway.hmac.signature");
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (!StringUtils.hasText(signature)) {
            return chain.filter(exchange);
        }

        ServerWebExchange mutatedExchange = exchange.mutate()
                .request(builder -> builder.headers(headers -> headers.set(INTERNAL_SIGNATURE_HEADER, signature)))
                .build();
        return chain.filter(mutatedExchange);
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 10;
    }
}
