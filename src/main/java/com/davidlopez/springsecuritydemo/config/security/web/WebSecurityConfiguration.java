package com.davidlopez.springsecuritydemo.config.security.web;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final UserAuthService userAuthService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .addFilter(requestHeaderAuthenticationFilter())
                .authorizeRequests()
                .anyRequest()
                .fullyAuthenticated()
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .cors()
                .and()
                .csrf()
                .disable()
                .headers().contentSecurityPolicy("test");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        PreAuthenticatedAuthenticationProvider preAuthenticatedAuthenticationProvider = new PreAuthenticatedAuthenticationProvider();
        preAuthenticatedAuthenticationProvider.setPreAuthenticatedUserDetailsService(userAuthService);
        auth.authenticationProvider(preAuthenticatedAuthenticationProvider);
    }

    private RequestHeaderAuthenticationFilter requestHeaderAuthenticationFilter() throws Exception {
        RequestHeaderAuthenticationFilter requestHeaderAuthenticationFilter = new RequestHeaderAuthenticationFilter();
        requestHeaderAuthenticationFilter.setAuthenticationManager(authenticationManager());
        requestHeaderAuthenticationFilter.setExceptionIfHeaderMissing(false);
        requestHeaderAuthenticationFilter.setPrincipalRequestHeader("API-KEY");
        return requestHeaderAuthenticationFilter;
    }
}
