package co.edu.uco.apigatewayservice.filter;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class InternalSignatureFilter implements GlobalFilter, Ordered {

    private static final String SIGNATURE_PLACEHOLDER = "<GATEWAY_HMAC_SIGNATURE>";

    private final String signature;

    public InternalSignatureFilter(@Value("${gateway.hmac.signature:}") String signature) {
        this.signature = signature;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (!hasSignatureConfigured()) {
            return chain.filter(exchange);
        }
        return chain.filter(exchange.mutate()
            .request(builder -> builder.headers(httpHeaders -> httpHeaders.set("X-Internal-Signature", signature)))
            .build());
    }

    private boolean hasSignatureConfigured() {
        return StringUtils.hasText(signature) && !SIGNATURE_PLACEHOLDER.equals(signature);
    }

    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE - 10;
    }
}
