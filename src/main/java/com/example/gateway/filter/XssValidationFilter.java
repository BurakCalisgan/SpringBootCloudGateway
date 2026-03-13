package com.example.gateway.filter;

import com.example.gateway.util.ErrorResponseUtil;
import com.example.gateway.util.XssInspector;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Optional;

@Component
@Slf4j
public class XssValidationFilter implements GlobalFilter, Ordered {

    private final XssInspector xssInspector;
    private final ErrorResponseUtil errorResponseUtil;

    public XssValidationFilter(XssInspector xssInspector, ErrorResponseUtil errorResponseUtil) {
        this.xssInspector = xssInspector;
        this.errorResponseUtil = errorResponseUtil;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, org.springframework.cloud.gateway.filter.GatewayFilterChain chain) {
        return DataBufferUtils.join(exchange.getRequest().getBody())
                .defaultIfEmpty(exchange.getResponse().bufferFactory().wrap(new byte[0]))
                .flatMap(dataBuffer -> inspectAndForward(exchange, chain, dataBuffer));
    }

    private Mono<Void> inspectAndForward(ServerWebExchange exchange,
                                         org.springframework.cloud.gateway.filter.GatewayFilterChain chain,
                                         DataBuffer dataBuffer) {
        byte[] bodyBytes = new byte[dataBuffer.readableByteCount()];
        dataBuffer.read(bodyBytes);
        DataBufferUtils.release(dataBuffer);

        Optional<String> violation = xssInspector.detectViolation(exchange.getRequest(), bodyBytes);
        if (violation.isPresent()) {
            log.warn("{} - {}", exchange.getRequest().getPath(), violation.get());
            return errorResponseUtil.sendErrorResponse(exchange, HttpStatus.BAD_REQUEST, violation.get());
        }

        ServerHttpRequest decoratedRequest = decorateRequest(exchange.getRequest(), bodyBytes);
        return chain.filter(exchange.mutate().request(decoratedRequest).build());
    }

    private ServerHttpRequest decorateRequest(ServerHttpRequest request, byte[] bodyBytes) {
        return new ServerHttpRequestDecorator(request) {
            @Override
            @NonNull
            public Flux<DataBuffer> getBody() {
                return Flux.defer(() -> Mono.just(DefaultDataBufferFactory.sharedInstance.wrap(bodyBytes)));
            }
        };
    }

    @Override
    public int getOrder() {
        return -100;
    }
}
