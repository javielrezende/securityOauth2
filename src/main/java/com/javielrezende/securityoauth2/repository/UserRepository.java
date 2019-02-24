package com.javielrezende.securityoauth2.repository;

import com.javielrezende.securityoauth2.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    public Optional<User> findByEmail(String email);

}
