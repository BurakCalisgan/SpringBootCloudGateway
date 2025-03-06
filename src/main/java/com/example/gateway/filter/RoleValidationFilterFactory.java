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
import org.springframework.cloud.gateway.route.Route;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
@Slf4j
public class RoleValidationFilterFactory extends AbstractGatewayFilterFactory<RoleValidationFilterFactory.Config> {

    private final AuthClient authClient;

    public RoleValidationFilterFactory(AuthClient authClient) {
        super(Config.class);
        this.authClient = authClient;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return new OrderedGatewayFilter((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String token = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            List<String> allowedRoles = getAllowedRolesFromMetadata(exchange);

            // Eğer allowedRoles boşsa, erişim engellensin
            if (allowedRoles.isEmpty()) {
                try {
                    return onError(exchange, "Access Denied (No Roles Allowed)");
                } catch (JsonProcessingException e) {
                    throw new RuntimeException(e);
                }
            }

            // Eğer PUBLIC erişim varsa, direkt devam et
            if (allowedRoles.contains("PUBLIC")) {
                return chain.filter(exchange);
            }

            return authClient.extractRole(token)
                    .flatMap(role -> {
                        if (!allowedRoles.contains(role)) {
                            try {
                                return onError(exchange, "Access Denied");
                            } catch (JsonProcessingException e) {
                                return Mono.error(new RuntimeException(e));
                            }
                        }
                        return chain.filter(exchange);
                    })
                    .onErrorResume(e -> {
                        try {
                            return onError(exchange, "Invalid Token");
                        } catch (JsonProcessingException ex) {
                            throw new RuntimeException(ex);
                        }
                    });
        }, 2); // TokenValidationFilter'tan sonra çalışacak
    }

    private List<String> getAllowedRolesFromMetadata(ServerWebExchange exchange) {
        Route route = exchange.getAttribute("org.springframework.cloud.gateway.support.ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR");

        if (route == null) {
            return List.of(); // Eğer route bilgisi yoksa, erişim engellenir
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

    private Mono<Void> onError(ServerWebExchange exchange, String err) throws JsonProcessingException {

        log.error("{} - {} ", exchange.getRequest().getPath(), err);

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("status", HttpStatus.FORBIDDEN.value());
        errorResponse.put("error", "Forbidden");
        errorResponse.put("message", err);
        errorResponse.put("path", exchange.getRequest().getPath().toString());

        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);  // 403 Forbidden
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

        // JSON body'yi yazma işlemi
        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse()
                .bufferFactory()
                .wrap(new ObjectMapper().writeValueAsBytes(errorResponse))));
    }

    public static class Config {
    }
}
