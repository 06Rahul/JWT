package com.example.SecurityAndJwt.DTO;

import com.example.SecurityAndJwt.Model.Role;
import lombok.*;

import java.util.Collection;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AppUserDTO {
    private Long id;
    private String username;
    private String email;
    private Collection<Role> roles;  // ✅ Include roles but no password
}
