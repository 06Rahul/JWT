package com.example.SecurityAndJwt.Repository;

import com.example.SecurityAndJwt.Model.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepo extends JpaRepository<AppUser , Long> {
     AppUser findByUsername(String username);


    AppUser findByEmail(String username);
}
