package com.example.SecurityAndJwt;

import com.example.SecurityAndJwt.Model.AppUser;
import com.example.SecurityAndJwt.Model.Role;
import com.example.SecurityAndJwt.Services.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.util.ArrayList;

@SpringBootApplication
public class SecurityAndJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityAndJwtApplication.class, args);
	}
@Bean
	CommandLineRunner run(UserService userService) {
		return args -> {
			// ✅ Ensure roles exist before assigning
			if (!userService.roleExists("ADMIN")) {
				userService.saveRole(new Role(null, "ADMIN"));
			}
			if (!userService.roleExists("USER")) {
				userService.saveRole(new Role(null, "USER"));
			}

			// ✅ Ensure user exists before assigning roles
			if (!userService.userExists("rahulmamgain269@gmail.com")) {
				userService.saveUser(new AppUser(null, "Rahul", "Pass123", "rahulmamgain269@gmail.com", new ArrayList<>()));
				userService.assignRoleToUser("rahulmamgain269@gmail.com", "ADMIN");
			}
		};
	}


}
