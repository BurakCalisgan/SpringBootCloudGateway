package com.example.gateway.filter;

import com.example.gateway.client.AuthClient;
import com.example.gateway.util.ErrorResponseUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.OrderedGatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class TokenValidationFilterFactory extends AbstractGatewayFilterFactory<TokenValidationFilterFactory.Config> {

    private final AuthClient authClient;
    private final ErrorResponseUtil errorResponseUtil;

    public TokenValidationFilterFactory(AuthClient authClient, ErrorResponseUtil errorResponseUtil) {
        super(Config.class);
        this.authClient = authClient;
        this.errorResponseUtil = errorResponseUtil;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return new OrderedGatewayFilter((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, "Missing Authorization Header");
            }

            String token = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            return authClient.validateToken(token)
                    .flatMap(isValid -> {
                        if (isValid) {
                            return chain.filter(exchange);
                        } else {
                            return onError(exchange, "Invalid Token");
                        }
                    })
                    .onErrorResume(e -> onError(exchange, "Invalid Token"));

        }, 1); // TokenFilter önce çalışmalı, sonra RoleFilter çalışacak
    }

    private Mono<Void> onError(ServerWebExchange exchange, String message) {
        log.error("{} - {}", exchange.getRequest().getPath(), message);
        return errorResponseUtil.sendErrorResponse(exchange, HttpStatus.UNAUTHORIZED, message);
    }

    public static class Config {
    }
}