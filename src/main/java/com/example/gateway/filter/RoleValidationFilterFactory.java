package com.example.gateway.filter;

import com.example.gateway.client.AuthClient;
import com.example.gateway.util.ErrorResponseUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.OrderedGatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

@Component
@Slf4j
public class RoleValidationFilterFactory extends AbstractGatewayFilterFactory<RoleValidationFilterFactory.Config> {

    private final AuthClient authClient;
    private final ErrorResponseUtil errorResponseUtil;

    public RoleValidationFilterFactory(AuthClient authClient, ErrorResponseUtil errorResponseUtil) {
        super(Config.class);
        this.authClient = authClient;
        this.errorResponseUtil = errorResponseUtil;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return new OrderedGatewayFilter((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String token = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            // Route metadata içindeki izin verilen rolleri al
            List<String> allowedRoles = getAllowedRolesFromMetadata(exchange);

            // Eğer route üzerinde herhangi bir rol tanımlanmamışsa erişim engellensin
            if (allowedRoles.isEmpty()) {
                return onError(exchange, HttpStatus.FORBIDDEN, "Access Denied (No Roles Allowed)");
            }

            // Eğer route "PUBLIC" olarak işaretlenmişse doğrudan erişime izin ver
            if (allowedRoles.contains("PUBLIC")) {
                return chain.filter(exchange);
            }

            // Auth microservisten token içindeki rolü al ve kontrol et
            return authClient.extractRole(token)
                    .flatMap(role -> {
                        if (!allowedRoles.contains(role)) {
                            return onError(exchange, HttpStatus.FORBIDDEN, "Access Denied");
                        }
                        return chain.filter(exchange);
                    })
                    .onErrorResume(e -> onError(exchange, HttpStatus.UNAUTHORIZED, "Invalid Token"));
        }, 2); // TokenValidationFilter'tan sonra çalışacak
    }

    /**
     * Route metadata'dan izin verilen rolleri çıkarır.
     */
    private List<String> getAllowedRolesFromMetadata(ServerWebExchange exchange) {
        Route route = exchange.getAttribute("org.springframework.cloud.gateway.support.ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR");

        if (route == null) {
            return List.of();
        }

        Map<String, Object> metadata = route.getMetadata();

        // Eğer allowedRoles metadatası yoksa, default olarak PUBLIC erişim ver
        if (!metadata.containsKey("allowedRoles")) {
            return List.of("PUBLIC");
        }

        Object rolesObj = metadata.get("allowedRoles");

        // Metadata yanlış formatta ise boş liste dön
        if (!(rolesObj instanceof List<?> rolesList)) {
            return List.of();
        }

        // Roller String değilse temizleyip dönüştür
        return rolesList.stream()
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .toList();
    }

    private Mono<Void> onError(ServerWebExchange exchange, HttpStatus status, String message) {
        log.error("{} - {}", exchange.getRequest().getPath(), message);
        return errorResponseUtil.sendErrorResponse(exchange, status, message);
    }

    public static class Config {
    }
}
