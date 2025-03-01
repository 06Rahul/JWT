package com.example.SecurityAndJwt.Configuration;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {

    @Bean
    public OpenAPI mySwaggerConfig(){
        return new OpenAPI().info(
                new Info().title("Spring Security And JWT API")
                        .description("this is a sample Spring Security And JWT API")
        );
    }
}
