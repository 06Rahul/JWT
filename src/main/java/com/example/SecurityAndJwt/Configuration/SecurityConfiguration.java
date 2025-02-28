package com.example.SecurityAndJwt.Configuration;

import com.example.SecurityAndJwt.Services.UserDetailServiceImpl;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

//    @Value("${SECRET_KEY}")
//    private String secretKey;

    private final UserDetailServiceImpl userDetailService;
    //private final String secretKey = "asdgakjfhkdsahkjvbdsabfvkahfgbawbfkhewabfkahrhcqiuhriuqgiurgiuqgiru"; // Hardcoded secret key

    public SecurityConfiguration(UserDetailServiceImpl userDetailService) {
        this.userDetailService = userDetailService;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        CustomAuthFilter customAuthFilter = new CustomAuthFilter(authenticationManager);
        customAuthFilter.setFilterProcessesUrl("/user/login"); // Set the login URL

        return http
                .csrf(csrf -> csrf.disable()) // Disable CSRF for testing (enable in production)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/user/**").permitAll()  // Allow user creation
                        .requestMatchers(HttpMethod.GET, "/user/roles/**").hasAnyRole("ADMIN", "USER") // Restrict GET roles
                        .requestMatchers(HttpMethod.GET, "/user/**").hasRole("ADMIN") // Restrict GET /user/**
                        .anyRequest().authenticated() // Authenticate everything else
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // Stateless session
                .authenticationProvider(authenticationProvider()) // Register authentication provider
                .addFilter(customAuthFilter) // Add Custom Auth Filter properly
                .addFilterBefore(new CustomAuthorizationFilter("secret"), UsernamePasswordAuthenticationFilter.class) // Add Custom Authorization Filter
                .httpBasic(Customizer.withDefaults()) // Enable HTTP Basic Auth
                .build();
    }

    @Bean
    public BCryptPasswordEncoder encoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(encoder());
        provider.setUserDetailsService(userDetailService);
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
}