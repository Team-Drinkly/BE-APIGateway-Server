package com.drinkhere.drinklygateway.filter;

import com.drinkhere.drinklygateway.response.ErrorCode;
import com.drinkhere.drinklygateway.response.ErrorResponse;
import com.drinkhere.drinklygateway.security.JwtTokenProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
@Slf4j
@RequiredArgsConstructor
public class GlobalAuthorizationFilter implements GlobalFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final ObjectMapper objectMapper = new ObjectMapper();

    // 인증 제외 경로 (ex: 회원가입, 로그인)
    private static final List<String> EXCLUDED_PATHS = List.of("/api/v1/member/login", "/api/v1/member/signup");

    // `api/v1/{service}/{role}/**` 패턴을 위한 정규식
    private static final Pattern PATH_PATTERN = Pattern.compile("^/api/v1/([^/]+)/([mo])/.*$");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String requestPath = request.getURI().getPath();

        log.info("[GlobalAuthorizationFilter] 요청 URL: {}", requestPath);

        // JWT 검증을 생략할 경로 확인
        if (EXCLUDED_PATHS.stream().anyMatch(requestPath::startsWith)) {
            log.info("인증 제외 경로 접근. JWT 검증 생략.");
            return chain.filter(exchange);
        }

        HttpHeaders headers = request.getHeaders();
        if (!headers.containsKey(HttpHeaders.AUTHORIZATION)) {
            log.warn("Authorization 헤더 없음.");
            return onError(exchange, HttpStatus.UNAUTHORIZED, ErrorCode.NOT_FOUND_JWT_TOKEN);
        }

        String token = headers.getFirst(HttpHeaders.AUTHORIZATION);
        if (token == null || !token.startsWith("Bearer ")) {
            return onError(exchange, HttpStatus.UNAUTHORIZED, ErrorCode.NOT_FOUND_JWT_TOKEN);
        }

        token = token.substring(7).trim();
        log.info("JWT 토큰 확인: {}", token);

        try {
            jwtTokenProvider.validateJwtToken(token);
            Matcher matcher = PATH_PATTERN.matcher(requestPath);

            if (matcher.matches()) {
                String service = matcher.group(1); // 서비스명 (ex: coupon, store)
                String role = matcher.group(2);    // m (멤버) or o (사장님)

                if ("m".equals(role)) {
                    return validateMemberToken(exchange, chain, request, token);
                } else if ("o".equals(role)) {
                    return validateOwnerToken(exchange, chain, request, token);
                }
            }

            return onError(exchange, HttpStatus.FORBIDDEN, ErrorCode.UNAUTHORIZED);

        } catch (Exception e) {
            log.error("JWT 인증 실패: {}", e.getMessage());
            return onError(exchange, HttpStatus.UNAUTHORIZED, ErrorCode.INVALID_JWT_TOKEN);
        }
    }

    /**
     * `/api/v1/{service}/m/**` 요청에 대한 멤버 검증
     */
    private Mono<Void> validateMemberToken(ServerWebExchange exchange, GatewayFilterChain chain, ServerHttpRequest request, String token) {
        String memberId = jwtTokenProvider.getMemberId(token);
        boolean isSubscribed = jwtTokenProvider.isSubscribed(token);

        if (!isSubscribed) {
            log.warn("구독되지 않은 멤버: {}", memberId);
            return onError(exchange, HttpStatus.FORBIDDEN, ErrorCode.UNAUTHORIZED);
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

        return response.writeWith(Mono.just(response.bufferFactory().wrap(responseBody)));
    }
}
