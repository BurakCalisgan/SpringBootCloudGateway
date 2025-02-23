package com.example.gateway.filter;

import com.example.gateway.client.AuthClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@Slf4j
@RequiredArgsConstructor
public class TokenValidationFilter implements GlobalFilter, Ordered {

    private final AuthClient authClient;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
            return onError(exchange, "Missing Authorization Header");
        }

        String token = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        return authClient.validateToken(token)
                .flatMap(response -> chain.filter(exchange))
                .onErrorResume(e -> onError(exchange, "Invalid Token"));

    }

    private Mono<Void> onError(ServerWebExchange exchange, String err) {
        log.error("{} - {} ", exchange.getRequest().getPath(), err);
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    @Override
    public int getOrder() {
        return 	Ordered.HIGHEST_PRECEDENCE;
    }
}
