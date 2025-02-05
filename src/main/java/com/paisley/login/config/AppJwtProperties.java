package com.paisley.login.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AppJwtProperties {

    @Value("${app.jwt.secretKey}")
    private String secretKey;

    @Value("${app.jwt.refreshSecretKey}")
    private String refreshSecretKey;

    public String getSecretKey() {
        return secretKey;
    }

    public String getRefreshSecretKey() {
        return refreshSecretKey;
    }
}
