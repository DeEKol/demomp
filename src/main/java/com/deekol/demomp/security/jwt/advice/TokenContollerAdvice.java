package com.deekol.demomp.security.jwt.advice;

import java.util.Date;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import com.deekol.demomp.security.jwt.exception.TokenRefreshException;

@RestControllerAdvice
public class TokenContollerAdvice {
	@ExceptionHandler(value = TokenRefreshException.class)
	@ResponseStatus(HttpStatus.FORBIDDEN)
	public ErrorMessage handlerTokenRefreshException(TokenRefreshException ex, WebRequest request) {
		return new ErrorMessage(
				HttpStatus.FORBIDDEN.value(),
				new Date(),
				ex.getMessage(),
				request.getDescription(false));
	}
}
