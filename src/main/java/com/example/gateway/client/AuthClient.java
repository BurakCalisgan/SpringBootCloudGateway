package com.example.gateway.client;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;
import java.time.Duration;

@Component
@RequiredArgsConstructor
public class AuthClient {

    private final WebClient.Builder webClientBuilder;

    @Value("${webclient.config.base-url}")
    private String authServiceUrl;

    @Value("${webclient.config.connect-timeout}")
    private int connectTimeout;

    @Value("${webclient.config.read-timeout}")
    private int readTimeout;

    private WebClient createWebClient() {
        HttpClient httpClient = HttpClient.create()
                .option(io.netty.channel.ChannelOption.CONNECT_TIMEOUT_MILLIS, connectTimeout) // Bağlantı timeout
                .responseTimeout(Duration.ofMillis(readTimeout)); // Yanıt timeout

        return webClientBuilder
                .baseUrl(authServiceUrl)
                .exchangeStrategies(ExchangeStrategies.builder()
                        .codecs(configurer -> configurer.defaultCodecs().maxInMemorySize(16 * 1024 * 1024))
                        .build())
                .clientConnector(new ReactorClientHttpConnector(httpClient)) // Güncellenmiş kullanım
                .build();
    }

    public Mono<String> validateToken(String token) {
        return createWebClient()
                .post()
                .uri("/validate-token")
                .header(HttpHeaders.AUTHORIZATION, token)
                .retrieve()
                .bodyToMono(String.class);
    }

    public Mono<String> extractRole(String token) {
        return createWebClient()
                .get()
                .uri("/extract-role")
                .header(HttpHeaders.AUTHORIZATION, token)
                .retrieve()
                .bodyToMono(String.class);
    }
}
