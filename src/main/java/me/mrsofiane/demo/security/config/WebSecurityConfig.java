package me.mrsofiane.demo.security.config;

import lombok.AllArgsConstructor;
import me.mrsofiane.demo.appuser.AppUserService;
import me.mrsofiane.demo.jwt.JwtTokenVerifier;
import me.mrsofiane.demo.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@AllArgsConstructor
@Deprecated
public class WebSecurityConfig {
/*
    private final AppUserService appUserService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.authorizeRequests().antMatchers("/api/v*//*registration/**").permitAll();
        http.authorizeRequests().anyRequest().authenticated();
        http.addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager()));
        http.addFilterBefore(new JwtTokenVerifier(), JwtUsernameAndPasswordAuthenticationFilter.class);

    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }


    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(bCryptPasswordEncoder);
        provider.setUserDetailsService(appUserService);
        return provider;
    }

    */
}
