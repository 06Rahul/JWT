package com.example.SecurityAndJwt.DTO;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Data
public class LogInBody {

    private String email;
    private String password;
}
