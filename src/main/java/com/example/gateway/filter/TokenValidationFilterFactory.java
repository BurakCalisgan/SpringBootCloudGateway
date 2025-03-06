package com.example.gateway.filter;

import com.example.gateway.client.AuthClient;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.OrderedGatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

@Component
@Slf4j
public class TokenValidationFilterFactory extends AbstractGatewayFilterFactory<TokenValidationFilterFactory.Config> {

    private final AuthClient authClient;

    public TokenValidationFilterFactory(AuthClient authClient) {
        super(Config.class);
        this.authClient = authClient;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return new OrderedGatewayFilter((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                try {
                    return onError(exchange, "Missing Authorization Header");
                } catch (JsonProcessingException e) {
                    throw new RuntimeException(e);
                }
            }

            String token = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            return authClient.validateToken(token)
                    .flatMap(response -> chain.filter(exchange))
                    .onErrorResume(e -> {
                        try {
                            return onError(exchange, "Invalid Token");
                        } catch (JsonProcessingException ex) {
                            throw new RuntimeException(ex);
                        }
                    });

        }, 1); // TokenFilter önce çalışmalı, sonra RoleFilter çalışacak
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err) throws JsonProcessingException {

        log.error("{} - {} ", exchange.getRequest().getPath(), err);

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("status", HttpStatus.UNAUTHORIZED.value());  // 401 status
        errorResponse.put("error", "Unauthorized");
        errorResponse.put("message", err);
        errorResponse.put("path", exchange.getRequest().getPath().toString());

        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);  // 401
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse()
                .bufferFactory()
                .wrap(new ObjectMapper().writeValueAsBytes(errorResponse))));
    }

    public static class Config {
    }
}
