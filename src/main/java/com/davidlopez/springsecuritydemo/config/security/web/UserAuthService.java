package com.davidlopez.springsecuritydemo.config.security.web;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class UserAuthService implements AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {

    @Value("${api.key}")
    private String apiKey;

    @Override
    public UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken token) throws UsernameNotFoundException {
        val requestApiKey = (String) token.getPrincipal();

       if (!apiKey.equals(requestApiKey)) throw new UsernameNotFoundException("Invalid API key");

       return AuthorizedUser.builder().password(requestApiKey).build();
    }
}
