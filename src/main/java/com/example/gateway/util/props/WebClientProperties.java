package com.example.gateway.util.props;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "webclient.config")
public class WebClientProperties {
    private String baseUrl;
    private int connectTimeout;
    private int readTimeout;
}

