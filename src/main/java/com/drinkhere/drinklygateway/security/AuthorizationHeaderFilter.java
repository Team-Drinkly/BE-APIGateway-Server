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

@Component
@Slf4j
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

    private final JwtTokenProvider jwtTokenProvider;
    private final ObjectMapper objectMapper = new ObjectMapper();

    // `/member/**` 경로는 JWT 검증 제외
    private static final List<String> EXCLUDED_PATHS = List.of("/member/");

    public AuthorizationHeaderFilter(JwtTokenProvider jwtTokenProvider) {
        super(Config.class);
        this.jwtTokenProvider = jwtTokenProvider;
    }

    public static class Config {
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String requestPath = request.getURI().getPath();
            log.info("AuthorizationHeaderFilter Start: {}", requestPath);

            // "/member/**" 경로는 JWT 검증 생략
            if (EXCLUDED_PATHS.stream().anyMatch(requestPath::startsWith)) {
                log.info("Member 관련 API 요청. JWT 검증 생략.");
                return chain.filter(exchange);
            }

            HttpHeaders headers = request.getHeaders();
            if (!headers.containsKey(HttpHeaders.AUTHORIZATION)) {
                log.warn("Authorization header is missing. Assigning guest user.");
                return assignGuestRole(exchange, chain);
            }

            String authorizationHeader = headers.getFirst(HttpHeaders.AUTHORIZATION);
            if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
                return onError(exchange, ErrorCode.INVALID_TOKEN, HttpStatus.UNAUTHORIZED);
            }

            // JWT 토큰 파싱
            String token = authorizationHeader.substring(7).trim();
            try {
                jwtTokenProvider.validateJwtToken(token);
                String userId = jwtTokenProvider.getSocialId(token);  // JWT에서 user-id 추출

                // 새 요청 생성 (기존 Authorization 제거, user-id 추가)
                ServerHttpRequest newRequest = request.mutate()
                        .headers(httpHeaders -> httpHeaders.remove(HttpHeaders.AUTHORIZATION)) // 기존 Authorization 제거
                        .header("user-id", userId) // user-id 추가
                        .build();

                log.info("Authorized user: {}", userId);
                return chain.filter(exchange.mutate().request(newRequest).build());

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

    private Mono<Void> assignGuestRole(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest newRequest = exchange.getRequest().mutate()
                .header("user-id", "guest")
                .build();
        return chain.filter(exchange.mutate().request(newRequest).build());
    }

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
