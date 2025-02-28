package com.example.SecurityAndJwt.Services;

import com.example.SecurityAndJwt.DTO.AppUserDTO;
import com.example.SecurityAndJwt.DTO.UserUpdateDTO;
import com.example.SecurityAndJwt.Model.AppUser;
import com.example.SecurityAndJwt.Model.Role;
import com.example.SecurityAndJwt.Repository.RoleRepo;
import com.example.SecurityAndJwt.Repository.UserRepo;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional
public class UserService {

    private final BCryptPasswordEncoder encoder;
    private final RoleRepo roleRepo;
    private final UserRepo repo;
    private final Logger log = LoggerFactory.getLogger(UserService.class);

    public List<AppUser> getAllUser() {
        log.info("Fetching all users");
        return repo.findAll();
    }

    public AppUser getUserByEmail(String email) {
        log.info("Fetching user by email: " + email);
        return repo.findByEmail(email);
    }

    public AppUser getById(Long id) {
        log.info("Fetching user by ID: " + id);
        return repo.findById(id).orElse(null);
    }

    @Transactional
    public AppUser saveUser(AppUser appUser) {
        appUser.setPassword(encoder.encode(appUser.getPassword()));
        log.info("Saving user with email: " + appUser.getEmail());

        // ✅ Ensure the user is not already present
        if (repo.findByEmail(appUser.getEmail()) != null) {
            log.warn("User with email {} already exists", appUser.getEmail());
            throw new RuntimeException("User already exists");
        }

        // ✅ Ensure roles are properly managed
        List<Role> managedRoles = new ArrayList<>();
        for (Role role : appUser.getRoles()) {
            Role managedRole = roleRepo.findByName(role.getName());
            if (managedRole == null) {
                log.info("Role '{}' not found, creating new one", role.getName());
                managedRole = roleRepo.save(new Role(null, role.getName())); // Persist new roles
            }
            managedRoles.add(managedRole);
        }
        appUser.setRoles(managedRoles); // Set only managed roles

        return repo.save(appUser);
    }


    public void deleteUser(String email) {
        log.info("Deleting user with email: " + email);
        AppUser appUser = repo.findByEmail(email);
        if (appUser == null) {
            log.error("User not found with email: " + email);
            return;
        }
        repo.delete(appUser);
    }

    public void deleteById(Long id) {
        log.info("Deleting user with ID: " + id);
        repo.deleteById(id);
    }

    public void updateUser(String email, UserUpdateDTO userUpdateDTO) {
        log.info("Updating user with email: " + email);
        AppUser appUser = repo.findByEmail(email);

        if (appUser == null) {
            log.error("User not found with email: " + email);
            throw new RuntimeException("User not found");
        }

        // Update only allowed fields
        if (userUpdateDTO.getUsername() != null) {
            appUser.setUsername(userUpdateDTO.getUsername());
        }
        if (userUpdateDTO.getPassword() != null && !userUpdateDTO.getPassword().isEmpty()) {
            appUser.setPassword(encoder.encode(userUpdateDTO.getPassword()));
        }
        if (userUpdateDTO.getEmail() != null) {
            appUser.setEmail(userUpdateDTO.getEmail());
        }

        repo.save(appUser);
    }

    public void updateUserById(Long id, UserUpdateDTO userUpdateDTO) {
        log.info("Updating user with ID: " + id);
        AppUser appUser = repo.findById(id).orElse(null);

        if (appUser == null) {
            log.error("User not found with ID: " + id);
            throw new RuntimeException("User not found");
        }

        if (userUpdateDTO.getUsername() != null) {
            appUser.setUsername(userUpdateDTO.getUsername());
        }
        if (userUpdateDTO.getPassword() != null && !userUpdateDTO.getPassword().isEmpty()) {
            appUser.setPassword(encoder.encode(userUpdateDTO.getPassword()));
        }
        if (userUpdateDTO.getEmail() != null) {
            appUser.setEmail(userUpdateDTO.getEmail());
        }

        repo.save(appUser);
    }

    @Transactional
    public AppUser assignRoleToUser(String email, String roleName) {
        log.info("Assigning role '{}' to user: {}", roleName, email);
        AppUser appUser = repo.findByEmail(email);
        if (appUser == null) {
            log.error("User not found with email: " + email);
            throw new RuntimeException("User not found");
        }

        Role role = roleRepo.findByName(roleName);
        if (role == null) {
            log.error("Role '{}' not found", roleName);
            throw new RuntimeException("Role not found");
        }

        if (!appUser.getRoles().contains(role)) {
            appUser.getRoles().add(role);
            return repo.save(appUser); // ✅ Now `role` is managed before saving
        } else {
            log.warn("User already has role: {}", roleName);
            return appUser;
        }
    }

    public AppUser removeRoleFromUser(String email, String roleName) {
        log.info("Removing role '{}' from user: {}", roleName, email);
        AppUser appUser = repo.findByEmail(email);
        if (appUser == null) {
            log.error("User not found with email: " + email);
            throw new RuntimeException("User not found");
        }

        Role role = roleRepo.findByName(roleName);
        if (role == null) {
            log.error("Role '{}' not found", roleName);
            throw new RuntimeException("Role not found");
        }

        if (!appUser.getRoles().contains(role)) {
            log.warn("User does not have role: " + roleName);
            return appUser;
        }

        appUser.getRoles().remove(role);
        return repo.save(appUser);
    }

    public Role saveRole(Role role) {
        log.info("Saving role: " + role.getName());
        Role existingRole = roleRepo.findByName(role.getName());
        if (existingRole != null) {
            log.warn("Role '{}' already exists", role.getName());
            return existingRole;
        }
        return roleRepo.save(role);
    }

    public boolean roleExists(String roleName) {
        return roleRepo.findByName(roleName) != null;
    }

    public boolean userExists(String email) {
        return repo.findByEmail(email) != null;
    }

    public AppUserDTO convertToDTO(AppUser appUser) {
        return new AppUserDTO(
                appUser.getId(),
                appUser.getUsername(),
                appUser.getEmail(),
                appUser.getRoles()
        );
    }
}
