package com.drinkhere.drinklygateway.security;

import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "jwt")
@Getter
@Setter
@Slf4j
public class JwtTokenProvider {

    private String secret;

    private JwtParser jwtParser;

    @PostConstruct
    public void init() {
        this.jwtParser = Jwts.parser().setSigningKey(secret);
    }

    public void validateJwtToken(String token) {
        try {
            jwtParser.parseClaimsJws(token);
        } catch (Exception e) {
            log.info("JWT 오류: {}", e.getMessage());
            throw e;
        }
    }

    public String getSocialId(String token) {
        return jwtParser.parseClaimsJws(token).getBody().getSubject();
    }
}
