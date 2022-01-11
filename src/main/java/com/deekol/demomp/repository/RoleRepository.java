package com.deekol.demomp.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.deekol.demomp.model.ERole;
import com.deekol.demomp.model.Role;

public interface RoleRepository extends JpaRepository<Role, Integer> {
	Optional<Role> findByName(ERole name);
}
