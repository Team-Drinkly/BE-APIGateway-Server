package com.drinkhere.drinklygateway.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;

@Component
@Slf4j
public class JwtTokenProvider {

    private final SecretKey secretKey;

    public JwtTokenProvider(@Value("${jwt.secret}") String secret) {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        this.secretKey = Keys.hmacShaKeyFor(keyBytes);
    }

    // JWT 검증 메서드
    public void validateJwtToken(String token) {
        try {
            log.info("Validating JWT Token: {}", token);
            Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);
            log.info("JWT Token is valid!");
        } catch (Exception e) {
            log.error("JWT 검증 중 오류 발생: {}", e.getMessage());
            throw e;
        }
    }

    // JWT에서 memberId 추출
    public String getMemberId(String token) {
        return getClaims(token).get("member-id", String.class);
    }

    // JWT에서 구독 여부 추출
    public boolean isSubscribed(String token) {
        return getClaims(token).get("isSubscribed", Boolean.class);
    }

    // JWT에서 ownerId 추출
    public String getOwnerId(String token) {
        return getClaims(token).get("owner-id", String.class);
    }

    // JWT Claims 추출
    private Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
