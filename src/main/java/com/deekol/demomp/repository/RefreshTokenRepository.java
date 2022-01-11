package com.deekol.demomp.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;

import com.deekol.demomp.model.RefreshToken;
import com.deekol.demomp.model.User;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
	Optional<RefreshToken> findById(Long id);
	
	Optional<RefreshToken> findByToken(String token);
	
	@Modifying
	int deleteByUser(User user);
}
