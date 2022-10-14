package com.yyit.cloud.uaa.auth.config;

import com.yyit.cloud.uaa.auth.properties.CorsProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

/**
 * spring security 配置
 */
@EnableWebSecurity
@EnableConfigurationProperties(CorsProperties.class)
public class SpringSecurityConfiguration {



    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        // @formatter:off
        http
                .authorizeRequests(authorizeRequests ->

                        authorizeRequests

                                .anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults());
        // @formatter:on

        return http.build();
    }

    @Bean
    public UserDetailsService users() {
        // @formatter:off
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("password")
                .roles("ADMIN").build();
        // @formatter:on

        return new InMemoryUserDetailsManager(user);
    }


    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring()
                .antMatchers("/style/**", "/script/**", "/favicon.ico");
    }


    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public CorsFilter corsFilter(CorsProperties cors) {
        UrlBasedCorsConfigurationSource corsConfigurationSource = new UrlBasedCorsConfigurationSource();
        corsConfigurationSource.registerCorsConfiguration("/**", cors.toCorsConfiguration());
        return new CorsFilter(corsConfigurationSource);
    }

}
