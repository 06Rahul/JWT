package com.example.SecurityAndJwt.Configuration;



    import com.auth0.jwt.JWT;
    import com.auth0.jwt.algorithms.Algorithm;
    import com.example.SecurityAndJwt.Utils.UserDetailsImpl;
    import com.fasterxml.jackson.databind.ObjectMapper;
    import jakarta.servlet.FilterChain;
    import jakarta.servlet.http.HttpServletRequest;
    import jakarta.servlet.http.HttpServletResponse;
    import org.springframework.beans.factory.annotation.Value;
    import org.springframework.security.authentication.AuthenticationManager;
    import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
    import org.springframework.security.core.Authentication;
    import org.springframework.security.core.AuthenticationException;
    import org.springframework.security.core.GrantedAuthority;
    import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

    import java.io.IOException;
    import java.util.Date;
    import java.util.HashMap;
    import java.util.Map;
    import java.util.stream.Collectors;

    // to Authenticate the User..



    public class CustomAuthFilter extends UsernamePasswordAuthenticationFilter {

//        @Value("${SECRET_KEY}")
//        private String secretKey;

        private final AuthenticationManager authenticationManager;

        public CustomAuthFilter(AuthenticationManager authenticationManager) {
            this.authenticationManager = authenticationManager;
            setFilterProcessesUrl("/user/login"); // Set the login URL
        }

        @Override
        public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
            try {
                // Read the request body and parse it into a Map
                Map<String, String> requestMap = new ObjectMapper().readValue(request.getInputStream(), Map.class);
                String email = requestMap.get("email"); // Use "email" instead of "username"
                String password = requestMap.get("password");

                // Log the credentials
                logger.info("Attempting authentication for email: " + email);
                logger.info("Password: " + password);

                // Create an authentication token
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(email, password);
                return authenticationManager.authenticate(authenticationToken);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException {
            UserDetailsImpl user = (UserDetailsImpl) authentication.getPrincipal();
            Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
            String accessToken = JWT.create()
                    .withSubject(user.getUsername())
                    .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000)) // 10 minutes
                    .withIssuer(request.getRequestURI())
                    .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                    .sign(algorithm);

            String refreshToken = JWT.create()
                    .withSubject(user.getUsername())
                    .withExpiresAt(new Date(System.currentTimeMillis() + 30 * 60 * 1000)) // 30 minutes
                    .withIssuer(request.getRequestURI())
                    .sign(algorithm);

            // Create a response body
            Map<String, String> tokens = new HashMap<>();
            tokens.put("access_token", accessToken);
            tokens.put("refresh_token", refreshToken);

            response.setContentType("application/json");
            new ObjectMapper().writeValue(response.getWriter(), tokens);
        }
    }