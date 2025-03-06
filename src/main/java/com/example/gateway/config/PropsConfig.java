package com.example.gateway.config;

import com.example.gateway.util.props.WebClientProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties({WebClientProperties.class})
public class PropsConfig {
}
