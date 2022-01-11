package com.deekol.demomp.security.service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.deekol.demomp.model.RefreshToken;
import com.deekol.demomp.repository.RefreshTokenRepository;
import com.deekol.demomp.repository.UserRepository;
import com.deekol.demomp.security.jwt.exception.TokenRefreshException;

@Service
public class RefreshTokenService {
	@Value("${jwt.token.refreshExpirationMs}")
	private Long refreshTokenDurationMs;
	
	private RefreshTokenRepository refreshTokenRepository;
	private UserRepository userRepository;
	
	public RefreshTokenService(RefreshTokenRepository refreshTokenRepository,
			UserRepository userRepository) {
		this.refreshTokenRepository = refreshTokenRepository;
		this.userRepository = userRepository;
	}
	
	public Optional<RefreshToken> findByToken(String token) {
		return refreshTokenRepository.findByToken(token);
	}
	
	public RefreshToken createRefreshToken(Long userId) {
		RefreshToken refreshToken = new RefreshToken();
		
		refreshToken.setUser(userRepository.findById(userId).get());
		refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
		refreshToken.setToken(UUID.randomUUID().toString());
		
		refreshToken = refreshTokenRepository.save(refreshToken);
		return refreshToken;
	}
	
	public RefreshToken verifyExpiration(RefreshToken token) {
		if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
			refreshTokenRepository.delete(token);
			throw new TokenRefreshException(token.getToken(), "Refresh token was expired. Please make a new signin request");
		}
		
		return token;
	}
	
	@Transactional
	public int deleteByUserId(Long userId) {
		return refreshTokenRepository.deleteByUser(userRepository.findById(userId).get());
	}
}
