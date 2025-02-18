package com.drinkhere.drinklygateway.security;

import io.jsonwebtoken.*;
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

    /**
     * JWT 검증 메서드
     */
    public void validateJwtToken(String token) {
        try {
            log.info("🔍 Validating JWT Token: {}", token);
            Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);
            log.info("✅ JWT Token is valid!");
        } catch (ExpiredJwtException e) {
            log.error("❌ JWT 만료됨: {}", e.getMessage());
            throw e;
        } catch (UnsupportedJwtException e) {
            log.error("❌ 지원되지 않는 JWT 형식: {}", e.getMessage());
            throw e;
        } catch (MalformedJwtException e) {
            log.error("❌ JWT 구조가 올바르지 않음: {}", e.getMessage());
            throw e;
        } catch (IllegalArgumentException e) {
            log.error("❌ JWT가 비어있거나 올바르지 않음: {}", e.getMessage());
            throw e;
        } catch (JwtException e) {
            log.error("❌ JWT 검증 실패: {}", e.getMessage());
            throw e;
        }
    }

    /**
     * JWT에서 memberId 추출
     */
    public String getMemberId(String token) {
        return getClaims(token).get("member-id", String.class);
    }

    /**
     * JWT에서 구독 여부 추출
     */
    public boolean isSubscribed(String token) {
        Boolean subscribed = getClaims(token).get("isSubscribed", Boolean.class);
        return subscribed != null && subscribed;  // null이면 false 반환
    }

    /**
     * JWT에서 subscribeId 추출
     */
    public Long getSubscribeId(String token) {
        return getClaims(token).get("subscribe-id", Long.class);
    }

    /**
     * JWT에서 ownerId 추출
     */
    public String getOwnerId(String token) {
        return getClaims(token).get("owner-id", String.class);
    }

    /**
     * JWT Claims 추출
     */
    private Claims getClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            log.warn("⚠ JWT 만료: {}", e.getMessage());
            throw e;
        } catch (Exception e) {
            log.warn("⚠ JWT Claims 추출 실패: {}", e.getMessage());
            throw e;
        }
    }
}
