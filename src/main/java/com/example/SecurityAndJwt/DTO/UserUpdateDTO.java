package com.example.SecurityAndJwt.DTO;

import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserUpdateDTO {

    @Size(min = 3, max = 20)
    private String username;

    @Size(min = 8)
    private String password;

    private String email; // Users can update their email but not roles
}
