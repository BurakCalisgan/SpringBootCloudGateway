package com.example.gateway.client;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class AuthClient {

    private final WebClient webClient;

    public Mono<Boolean> validateToken(String token) {
        return webClient.post()
                .uri("/validate-token")
                .header(HttpHeaders.AUTHORIZATION, token)
                .retrieve()
                .toBodilessEntity() // Body'yi almıyoruz, sadece status code ve headers'ı alıyoruz
                .map(response -> response.getStatusCode().is2xxSuccessful()); // 2xx başarılı ise true, değilse false döner
    }

    public Mono<String> extractRole(String token) {
        return webClient.get()
                .uri("/extract-role")
                .header(HttpHeaders.AUTHORIZATION, token)
                .retrieve()
                .bodyToMono(String.class);
    }
}
