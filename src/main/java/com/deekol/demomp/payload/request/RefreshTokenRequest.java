package com.deekol.demomp.payload.request;

import javax.validation.constraints.NotBlank;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RefreshTokenRequest {
	@NotBlank
	private String refreshToken;
}
