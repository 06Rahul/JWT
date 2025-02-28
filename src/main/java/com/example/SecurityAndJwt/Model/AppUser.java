package com.example.SecurityAndJwt.Model;

import jakarta.persistence.*;
import jakarta.validation.constraints.Size;
import lombok.*;

import java.util.ArrayList;
import java.util.Collection;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class AppUser {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Size(min = 3, max = 20)
    @Column(unique = true, nullable = false)
    private String username;

    @Size(min = 8)
    @Column(nullable = false)
    private String password;

    @Column(unique = true, nullable = false)
    private String email;  // Changed from "Email" to "email" (camelCase)

    @ManyToMany(fetch = FetchType.EAGER , cascade = CascadeType.ALL )
    private Collection<Role> roles = new ArrayList<>();
}
