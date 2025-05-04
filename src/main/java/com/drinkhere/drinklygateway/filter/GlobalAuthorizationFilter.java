package com.drinkhere.drinklygateway.filter;

import com.drinkhere.drinklygateway.response.ErrorCode;
import com.drinkhere.drinklygateway.response.ErrorResponse;
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
import java.util.regex.Pattern;

@Component
@Slf4j
@RequiredArgsConstructor
public class GlobalAuthorizationFilter implements GlobalFilter {

    private final ObjectMapper objectMapper = new ObjectMapper();

    private static final List<Pattern> EXCLUDED_PATHS = List.of(
            Pattern.compile("^/api/v1/config/.*"), // Config 서버 API 인증 제외
            Pattern.compile("^/api/v1/member/(?!n/).*"), // 멤버 관련 API 인증 제외
            Pattern.compile("^/api/v1/.*/actuators/.*$"), // Actuator API 인증 제외
            Pattern.compile("^/api/v1/.*/swagger-ui/.*$"), // 모든 서비스의 Swagger UI 인증 제외
            Pattern.compile("^/api/v1/.*/api-docs$"),
            Pattern.compile("^/api/v1/.*/api-docs/.*$"),
            Pattern.compile("^/api/v1/store/o$"),
            Pattern.compile("^/api/v1/store/m/list$"),
            Pattern.compile("^/api/v1/store/m/list/\\d+$"), // /api/v1/store/m/{storeId} 경로 (숫자만) 제외
            Pattern.compile("^/api/v1/store/m/list/\\d+/name$"),
            Pattern.compile("^/api/v1/store/m/free-drink/client/.*$"),
            Pattern.compile("^/api/v1/payment/m/coupons/expired"),
            Pattern.compile("^/api/v1/payment/m/coupons/expire")
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String requestPath = request.getURI().getPath();
        log.info("[GlobalAuthorizationFilter] 요청 URL: {}", requestPath);

        if (EXCLUDED_PATHS.stream().anyMatch(pattern -> pattern.matcher(requestPath).matches())) {
            return chain.filter(exchange);
        }

        HttpHeaders headers = request.getHeaders();
        if (!headers.containsKey("member-id") && !headers.containsKey("owner-id")) {
            log.warn("JWT 검증이 완료되지 않음. member-id 또는 owner-id 없음.");
            return onError(exchange, HttpStatus.UNAUTHORIZED, ErrorCode.NOT_FOUND_JWT_TOKEN);
        }

        return chain.filter(exchange);
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
