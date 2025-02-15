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

    // JWT 검증 메서드 (Secret Key 사용)
    public void validateJwtToken(String token) {
        try {
            log.info("Validating JWT Token: {}", token); // 토큰 로그 추가
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

    // JWT에서 user-id 추출
    public String getSocialId(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
        String userId = claims.get("user-id", String.class);
        log.info("Extracted User ID: {}", userId);  // UserID 로그 추가
        return userId;
    }
}
