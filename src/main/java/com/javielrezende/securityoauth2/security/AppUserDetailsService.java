package com.javielrezende.securityoauth2.security;

import com.javielrezende.securityoauth2.model.User;
import com.javielrezende.securityoauth2.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Service
public class AppUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;


    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

        Optional<User> userOptional = userRepository.findByEmail(email);

        User user = userOptional.orElseThrow(() -> new UsernameNotFoundException("Usuário e/ou senha incorretos!"));

        return new org.springframework.security.core.userdetails.User(email, user.getSenha(), getPermitions(user));
    }

    private Collection<? extends GrantedAuthority> getPermitions(User user) {
        Set<SimpleGrantedAuthority> authorities = new HashSet<>();
        user.getPermissoes().forEach(p -> authorities.add(new SimpleGrantedAuthority(p.getDescricao().toUpperCase())));
        return authorities;
    }
}
