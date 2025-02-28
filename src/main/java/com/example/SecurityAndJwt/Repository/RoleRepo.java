package com.example.SecurityAndJwt.Repository;

import com.example.SecurityAndJwt.Model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepo extends JpaRepository<Role, Long> {
    Role findByName(String name);
}
