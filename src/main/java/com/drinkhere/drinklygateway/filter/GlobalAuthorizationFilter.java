package com.drinkhere.drinklygateway.filter;

import com.drinkhere.drinklygateway.response.ErrorCode;
import com.drinkhere.drinklygateway.response.ErrorResponse;
import com.drinkhere.drinklygateway.security.JwtTokenProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.List;

@Component
@Slf4j
@RequiredArgsConstructor
public class GlobalAuthorizationFilter implements GlobalFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        log.info("[GlobalAuthorizationFilter] 요청 URL: {}", request.getURI());

        HttpHeaders headers = request.getHeaders();

        // Authorization 헤더 확인
        if (!headers.containsKey(HttpHeaders.AUTHORIZATION)) {
            log.warn("Authorization 헤더 없음. 게스트로 요청 처리.");
            return continueWithGuestRole(exchange, chain);
        }

        List<String> authHeaders = headers.get(HttpHeaders.AUTHORIZATION);
        if (authHeaders == null || authHeaders.isEmpty()) {
            return onError(exchange, HttpStatus.UNAUTHORIZED, ErrorCode.NOT_FOUND_JWT_TOKEN);
        }

        String token = authHeaders.get(0).replace("Bearer ", "").trim();
        log.info("JWT 토큰 확인: {}", token);

        try {
            // 토큰 검증
            jwtTokenProvider.validateJwtToken(token);
            String userId = jwtTokenProvider.getSocialId(token);

            // 요청에 user-id 추가
            ServerHttpRequest newRequest = request.mutate()
                    .header("user-id", userId)
                    .build();

            return chain.filter(exchange.mutate().request(newRequest).build());

        } catch (Exception e) {
            log.error("JWT 인증 실패: {}", e.getMessage());
            return onError(exchange, HttpStatus.UNAUTHORIZED, ErrorCode.INVALID_JWT_TOKEN);
        }
    }

    private Mono<Void> continueWithGuestRole(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest newRequest = exchange.getRequest().mutate()
                .header("user-id", "guest")
                .build();
        return chain.filter(exchange.mutate().request(newRequest).build());
    }

    private Mono<Void> onError(ServerWebExchange exchange, HttpStatus status, ErrorCode errorCode) {
        log.error("JWT 인증 실패 - 상태 코드: {}, 에러 코드: {}", status, errorCode);

        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        ErrorResponse<Object> errorResponse = new ErrorResponse<>(errorCode);
        byte[] responseBody;
        try {
            responseBody = objectMapper.writeValueAsBytes(errorResponse);
        } catch (Exception e) {
            responseBody = "{\"message\": \"JSON 변환 오류\"}".getBytes(StandardCharsets.UTF_8);
        }

        DataBuffer buffer = response.bufferFactory().wrap(responseBody);
        return response.writeWith(Mono.just(buffer));
    }
}

