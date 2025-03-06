package com.example.gateway.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;

@Component
@RequiredArgsConstructor
public class ErrorResponseUtil {

    private final ObjectMapper objectMapper;

    public Mono<Void> sendErrorResponse(ServerWebExchange exchange, HttpStatus status, String message) {
        try {
            Map<String, Object> errorResponse = Map.of(
                    "status", status.value(),
                    "error", status.getReasonPhrase(),
                    "message", message,
                    "path", exchange.getRequest().getPath().toString()
            );

            byte[] jsonResponse = objectMapper.writeValueAsBytes(errorResponse);

            exchange.getResponse().setStatusCode(status);
            exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
            exchange.getResponse().getHeaders().setContentLength(jsonResponse.length);

            return exchange.getResponse().writeWith(
                    Mono.just(exchange.getResponse().bufferFactory().wrap(jsonResponse))
            );
        } catch (Exception e) {
            return exchange.getResponse().setComplete();
        }
    }
}
