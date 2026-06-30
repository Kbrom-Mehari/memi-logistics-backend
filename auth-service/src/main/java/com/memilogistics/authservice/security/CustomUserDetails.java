package com.memilogistics.authservice.security;

import com.memilogistics.authservice.entity.User;
import lombok.Getter;
import lombok.NonNull;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

@Getter
public class CustomUserDetails implements UserDetails {
    private final String id;

    private final String username;

    private final String password;

    private final Set<GrantedAuthority> authorities;

    public CustomUserDetails(User user) {
        this.id = user.getId();
        this.username = user.getEmail();
        this.password = user.getPassword();

        Set<GrantedAuthority> auths = new HashSet<>();
        user.getRoles()
                .stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.name()))
                .forEach(auths::add);
        user.getPermissions()
                .stream()
                .map(permission -> new SimpleGrantedAuthority("PERMISSION_" + permission.name()))
                .forEach(auths::add);

        this.authorities = auths;
    }

    @Override
    @NonNull
    public String getUsername() {
        return username;
    }


    @Override
    @NonNull
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }


    @Override
    public String getPassword() {
        return password;
    }


    @Override
    public boolean isAccountNonExpired() {
        return true;
    }


    @Override
    public boolean isAccountNonLocked() {
        return true;
    }


    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }


    @Override
    public boolean isEnabled() {
        return true;
    }
}
