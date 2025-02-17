package com.drinkhere.drinklygateway.security;

import com.drinkhere.drinklygateway.response.ErrorCode;
import com.drinkhere.drinklygateway.response.ErrorResponse;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
@Slf4j
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

    private final JwtTokenProvider jwtTokenProvider;
    private final ObjectMapper objectMapper;

    // 인증이 필요 없는 경로 리스트 (회원가입, 로그인 등)
    private static final List<String> EXCLUDED_PATHS = List.of("/api/v1/member/login", "/api/v1/member/signup");

    // 경로 패턴 `/api/v1/{service}/{role}/**`
    private static final Pattern PATH_PATTERN = Pattern.compile("^/api/v1/([^/]+)/([mo])/.*$");

    public AuthorizationHeaderFilter(JwtTokenProvider jwtTokenProvider, ObjectMapper objectMapper) {
        super(Config.class);
        this.jwtTokenProvider = jwtTokenProvider;
        this.objectMapper = objectMapper;
    }

    public static class Config {
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String requestPath = request.getURI().getPath();
            log.info("AuthorizationHeaderFilter Start: {}", requestPath);

            // 특정 경로에서는 인증을 생략
            if (EXCLUDED_PATHS.stream().anyMatch(requestPath::startsWith)) {
                log.info("인증 제외 경로. JWT 검증 생략.");
                return chain.filter(exchange);
            }

            HttpHeaders headers = request.getHeaders();
            if (!headers.containsKey(HttpHeaders.AUTHORIZATION)) {
                log.warn("Authorization 헤더 없음. 게스트 사용자로 처리.");
                return assignGuestRole(exchange, chain);
            }

            String authorizationHeader = headers.getFirst(HttpHeaders.AUTHORIZATION);
            if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
                return onError(exchange, ErrorCode.INVALID_TOKEN, HttpStatus.UNAUTHORIZED);
            }

            String token = authorizationHeader.substring(7).trim();
            try {
                jwtTokenProvider.validateJwtToken(token);
                Matcher matcher = PATH_PATTERN.matcher(requestPath);

                if (matcher.matches()) {
                    String service = matcher.group(1); // 서비스명 (예: coupon, store)
                    String role = matcher.group(2);    // m (멤버) or o (사장님)

                    if ("m".equals(role)) {
                        return validateMemberToken(exchange, chain, request, token);
                    } else if ("o".equals(role)) {
                        return validateOwnerToken(exchange, chain, request, token);
                    }
                }

                return onError(exchange, ErrorCode.UNAUTHORIZED, HttpStatus.FORBIDDEN);

            } catch (ExpiredJwtException e) {
                return onError(exchange, ErrorCode.EXPIRED_JWT, HttpStatus.UNAUTHORIZED);
            } catch (UnsupportedJwtException | MalformedJwtException | IllegalArgumentException e) {
                return onError(exchange, ErrorCode.INVALID_JWT_TOKEN, HttpStatus.UNAUTHORIZED);
            } catch (Exception e) {
                log.error("JWT 검증 중 예기치 않은 오류 발생", e);
                return onError(exchange, ErrorCode.INTERNAL_SERVER_ERROR, HttpStatus.INTERNAL_SERVER_ERROR);
            }
        };
    }

    /**
     * `/api/v1/{service}/m/**` 요청에 대한 멤버 검증
     */
    private Mono<Void> validateMemberToken(ServerWebExchange exchange, GatewayFilterChain chain, ServerHttpRequest request, String token) {
        String memberId = jwtTokenProvider.getMemberId(token);
        boolean isSubscribed = jwtTokenProvider.isSubscribed(token);

        if (!isSubscribed) {
            log.warn("구독되지 않은 멤버: {}", memberId);
            return onError(exchange, ErrorCode.UNAUTHORIZED, HttpStatus.FORBIDDEN);
        }

        ServerHttpRequest newRequest = request.mutate()
                .headers(httpHeaders -> httpHeaders.remove(HttpHeaders.AUTHORIZATION))
                .header("member-id", memberId)
                .build();

        log.info("멤버 인증 성공: {}", memberId);
        return chain.filter(exchange.mutate().request(newRequest).build());
    }

    /**
     * `/api/v1/{service}/o/**` 요청에 대한 사장님 검증
     */
    private Mono<Void> validateOwnerToken(ServerWebExchange exchange, GatewayFilterChain chain, ServerHttpRequest request, String token) {
        String ownerId = jwtTokenProvider.getOwnerId(token);

        ServerHttpRequest newRequest = request.mutate()
                .headers(httpHeaders -> httpHeaders.remove(HttpHeaders.AUTHORIZATION))
                .header("owner-id", ownerId)
                .build();

        log.info("사장님 인증 성공: {}", ownerId);
        return chain.filter(exchange.mutate().request(newRequest).build());
    }

    /**
     * Authorization 헤더가 없을 경우 "guest"로 처리
     */
    private Mono<Void> assignGuestRole(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest newRequest = exchange.getRequest().mutate()
                .header("user-id", "guest")
                .build();
        return chain.filter(exchange.mutate().request(newRequest).build());
    }

    /**
     * JWT 인증 실패 시 JSON 응답 반환
     */
    private Mono<Void> onError(ServerWebExchange exchange, ErrorCode errorCode, HttpStatus status) {
        log.warn("Authorization error: {} - {}", status, errorCode);

        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        ErrorResponse<?> responseBody = new ErrorResponse<>(errorCode);

        try {
            byte[] bytes = objectMapper.writeValueAsBytes(responseBody);
            DataBuffer buffer = response.bufferFactory().wrap(bytes);
            return response.writeWith(Flux.just(buffer));
        } catch (JsonProcessingException e) {
            log.error("JSON 변환 오류", e);
            return response.setComplete();
        }
    }
}
