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

import java.util.List;
import java.util.Map;

import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.cloud.gateway.route.Route;

@Component
@Slf4j
@RequiredArgsConstructor
public class RoleValidationFilter implements GlobalFilter, Ordered {

    private final AuthClient authClient;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String token = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        List<String> allowedRoles = getAllowedRolesFromMetadata(exchange);

        // Eğer allowedRoles BOŞSA, kimse erişemez
        if (allowedRoles.isEmpty()) {
            return onError(exchange, "Access Denied (No Roles Allowed)");
        }

        // Eğer PUBLIC erişim varsa, direkt devam et
        if (allowedRoles.contains("PUBLIC")) {
            return chain.filter(exchange);
        }

        return authClient.extractRole(token)
                .flatMap(role -> {
                    if (!allowedRoles.contains(role)) {
                        return onError(exchange, "Access Denied");
                    }
                    return chain.filter(exchange);
                })
                .onErrorResume(e -> onError(exchange, "Invalid Token"));
    }

    private List<String> getAllowedRolesFromMetadata(ServerWebExchange exchange) {
        Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);

        if (route == null) {
            return List.of(); // Eğer route bilgisi yoksa, boş liste dönelim (kimse erişemez)
        }

        Map<String, Object> metadata = route.getMetadata();

        if (!metadata.containsKey("allowedRoles")) {
            return List.of("PUBLIC"); // Eğer tanımlı değilse, HERKESE AÇIK OLSUN
        }

        Object rolesObj = metadata.get("allowedRoles");

        // Metadata içinde allowedRoles yanlış türdeyse, boş liste dön
        if (!(rolesObj instanceof List<?> rolesList)) {
            return List.of();
        }

        // Roller String değilse, temizleyelim
        return rolesList.stream()
                .filter(String.class::isInstance)  // Sadece String olanları al
                .map(String.class::cast)          // Cast işlemi yap
                .toList();                        // Listeye çevir
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err) {
        log.error("{} - {} ", exchange.getRequest().getPath(), err);
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        return exchange.getResponse().setComplete();
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 1;
    }
}

