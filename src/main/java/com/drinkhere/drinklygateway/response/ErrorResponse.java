package com.drinkhere.drinklygateway.response;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public class ErrorResponse<T> {
    private Boolean isSuccess;
    private String errorCode;
    private String message;

    public ErrorResponse(String errorCode, String message) {
        this.isSuccess = false;
        this.errorCode = errorCode;
        this.message = message;
    }

    public ErrorResponse(ErrorCode errorCode, String message) {
        this.isSuccess = false;
        this.errorCode = errorCode.getErrorCode();
        this.message = message;
    }

    public ErrorResponse(ErrorCode errorCode) {
        this.isSuccess = false;
        this.errorCode = errorCode.getErrorCode();
        this.message = errorCode.getMessage();
    }
}