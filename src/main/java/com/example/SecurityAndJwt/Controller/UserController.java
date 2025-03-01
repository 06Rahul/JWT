//package com.example.SecurityAndJwt.Controller;
//
//import com.example.SecurityAndJwt.DTO.AppUserDTO;
//import com.example.SecurityAndJwt.DTO.LogInBody;
//import com.example.SecurityAndJwt.DTO.UserUpdateDTO;
//import com.example.SecurityAndJwt.Model.AppUser;
//import com.example.SecurityAndJwt.Model.Role;
//import com.example.SecurityAndJwt.Services.UserService;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.access.prepost.PreAuthorize;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.web.bind.annotation.*;
//
//import java.util.HashMap;
//import java.util.List;
//import java.util.Map;
//
//@RestController
//@RequestMapping("/user")
//public class UserController {
//
//    private final AuthenticationManager authenticationManager;
//    private final UserService userService;
//    private final Logger log = LoggerFactory.getLogger(UserController.class);
//
//    public UserController(UserService userService, AuthenticationManager authenticationManager) {
//        this.userService = userService;
//        this.authenticationManager = authenticationManager;
//    }
//
//    @GetMapping("/")
//    public ResponseEntity<?> getAllUsers() {
//        log.trace("Fetching all users");
//        List<AppUser> appUsers = userService.getAllUser();
//        return ResponseEntity.ok(appUsers);
//    }
//
//    @PostMapping("/")
//    public ResponseEntity<?> addUser(@RequestBody AppUser appUser) {
//        log.info("Adding user with email: " + appUser.getEmail());
//        AppUser user = userService.saveUser(appUser);
//        return new ResponseEntity<>(user, HttpStatus.CREATED);
//    }
//
//    @GetMapping("/{email}")
//    public ResponseEntity<?> getUserByEmail(@PathVariable String email) {
//        log.info("Fetching user by email: " + email);
//        AppUser appUser = userService.getUserByEmail(email);
//        if (appUser == null) {
//            return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
//        }
//        return ResponseEntity.ok(appUser);
//    }
//
//    @DeleteMapping("/{email}")
//    public ResponseEntity<?> deleteUser(@PathVariable String email) {
//        log.info("Deleting user by email: " + email);
//        userService.deleteUser(email);
//        return ResponseEntity.ok("User deleted");
//    }
//
//    @DeleteMapping("/id/{id}")
//    public ResponseEntity<?> deleteUserById(@PathVariable Long id) {
//        log.info("Deleting user by ID: " + id);
//        userService.deleteById(id);
//        return ResponseEntity.ok("User deleted");
//    }
//
//    @GetMapping("/id/{id}")
//    public ResponseEntity<?> getUserById(@PathVariable Long id) {
//        log.info("Fetching user by ID: " + id);
//        AppUser appUser = userService.getById(id);
//        if (appUser == null) {
//            return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
//        }
//        return ResponseEntity.ok(appUser);
//    }
//
//    @PutMapping("/")
//    public ResponseEntity<?> updateUser(@RequestBody AppUser appUser) {
//        log.info("Updating user with email: " + appUser.getEmail());
//        AppUser user = userService.saveUser(appUser);
//        return new ResponseEntity<>(user, HttpStatus.OK);
//    }
//
//    @PutMapping("/email/{email}")
//    @PreAuthorize("authentication.principal.username == #email") // Users can update their own info
//    public ResponseEntity<?> updateUserByEmail(@PathVariable String email, @RequestBody UserUpdateDTO userUpdateDTO) {
//        log.info("Updating user by email: " + email);
//        userService.updateUser(email, userUpdateDTO);
//        return ResponseEntity.ok("User updated successfully");
//    }
//
//    @PutMapping("/id/{id}")
//    @PreAuthorize("hasRole('ADMIN')") // Only Admin can update users by ID
//    public ResponseEntity<?> updateUserById(@PathVariable Long id, @RequestBody UserUpdateDTO userUpdateDTO) {
//        log.info("Admin updating user by ID: " + id);
//        userService.updateUserById(id, userUpdateDTO);
//        return ResponseEntity.ok("User updated successfully");
//    }
//
//    @PostMapping("/assign-role")
//    public ResponseEntity<?> assignRoleToUser(@RequestParam String email, @RequestParam String roleName) {
//        log.info("Assigning role '" + roleName + "' to user: " + email);
//        AppUser appUser = userService.getUserByEmail(email);
//        if (appUser == null) {
//            return new ResponseEntity<>("User not found with email: " + email, HttpStatus.NOT_FOUND);
//        }
//        userService.assignRoleToUser(email, roleName);
//        return ResponseEntity.ok("Role assigned to user");
//    }
//
//    @GetMapping("/roles/{email}")
//    @PreAuthorize("hasRole('ADMIN') or authentication.principal.username == #email")
//    public ResponseEntity<?> getAllRolesOfUser(@PathVariable String email) {
//        log.info("Fetching all roles of user: " + email);
//        AppUser appUser = userService.getUserByEmail(email);
//        if (appUser == null) {
//            return new ResponseEntity<>("User not found with email: " + email, HttpStatus.NOT_FOUND);
//        }
//        return ResponseEntity.ok(appUser.getRoles());
//    }
//
//    @PostMapping("/remove-role")
//    public ResponseEntity<?> removeRoleFromUser(@RequestParam String email, @RequestParam String roleName) {
//        log.info("Removing role '" + roleName + "' from user: " + email);
//        AppUser appUser = userService.getUserByEmail(email);
//        if (appUser == null) {
//            return new ResponseEntity<>("User not found with email: " + email, HttpStatus.NOT_FOUND);
//        }
//        userService.removeRoleFromUser(email, roleName);
//        return ResponseEntity.ok("Role removed from user");
//    }
//
////    @PostMapping("/login")
////    public ResponseEntity<?> login(@RequestBody LogInBody body) {
////        log.trace("Logging in user with email: " + body.getEmail());
////
////        AppUser appUser = userService.getUserByEmail(body.getEmail());
////        if (appUser == null) {
////            return new ResponseEntity<>("User not found with email: " + body.getEmail(), HttpStatus.NOT_FOUND);
////        }
////
////        try {
////            Authentication authentication = authenticationManager.authenticate(
////                    new UsernamePasswordAuthenticationToken(body.getEmail(), body.getPassword())
////            );
////
////            SecurityContextHolder.getContext().setAuthentication(authentication);
////
////            // ✅ Create Response Object with User Details
////            Map<String, Object> response = new HashMap<>();
////
////            response.put("message", "User logged in successfully");
////            response.put("email", appUser.getEmail());
////            response.put("username", appUser.getUsername());
////            response.put("roles", appUser.getRoles().stream().map(Role::getName).toList());
////
////            return ResponseEntity.ok(response);
////
////        } catch (Exception e) {
////            log.error("Login failed for user: " + body.getEmail(), e);
////            return new ResponseEntity<>("Invalid credentials", HttpStatus.UNAUTHORIZED);
////        }
////    }
//@PostMapping("/login")
//public ResponseEntity<?> login(@RequestBody LogInBody body) {
//    log.trace("Logging in user with email: " + body.getEmail());
//
//    AppUser appUser = userService.getUserByEmail(body.getEmail());
//    if (appUser == null) {
//        return new ResponseEntity<>("User not found with email: " + body.getEmail(), HttpStatus.NOT_FOUND);
//    }
//
//    try {
//        Authentication authentication = authenticationManager.authenticate(
//                new UsernamePasswordAuthenticationToken(body.getEmail(), body.getPassword())
//        );
//
//        SecurityContextHolder.getContext().setAuthentication(authentication);
//
//        // ✅ Convert AppUser to Secure DTO (No password exposure)
//        AppUserDTO userDTO = userService.convertToDTO(appUser);
//
//        // ✅ Create Response Object with Message + Secure User Data
//        Map<String, Object> response = new HashMap<>();
//        response.put("message", "User logged in successfully");
//        response.put("user", userDTO);
//
//        return ResponseEntity.ok(response);
//
//    } catch (Exception e) {
//        log.error("Login failed for user: " + body.getEmail(), e);
//        return new ResponseEntity<>("Invalid credentials", HttpStatus.UNAUTHORIZED);
//    }
//}
//
//
//}

package com.example.SecurityAndJwt.Controller;

import com.example.SecurityAndJwt.DTO.UserUpdateDTO;
import com.example.SecurityAndJwt.Model.AppUser;
import com.example.SecurityAndJwt.Services.UserService;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/user")
@Tag(name = "User API", description = "Provides the user API")
public class UserController {

    private final UserService userService;
    private final Logger log = LoggerFactory.getLogger(UserController.class);

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @Tag(name = "Fetch All User")
    @GetMapping("/")
    public ResponseEntity<?> getAllUsers() {
        log.trace("Fetching all users");
        List<AppUser> appUsers = userService.getAllUser();
        return ResponseEntity.ok(appUsers);
    }

    @PostMapping("/")
    public ResponseEntity<?> addUser(@RequestBody AppUser appUser) {
        log.info("Adding user with email: " + appUser.getEmail());
        AppUser user = userService.saveUser(appUser);
        return new ResponseEntity<>(user, HttpStatus.CREATED);
    }

    @GetMapping("/{email}")
    public ResponseEntity<?> getUserByEmail(@PathVariable String email) {
        log.info("Fetching user by email: " + email);
        AppUser appUser = userService.getUserByEmail(email);
        if (appUser == null) {
            return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
        }
        return ResponseEntity.ok(appUser);
    }

    @DeleteMapping("/{email}")
    public ResponseEntity<?> deleteUser(@PathVariable String email) {
        log.info("Deleting user by email: " + email);
        userService.deleteUser(email);
        return ResponseEntity.ok("User deleted");
    }

    @DeleteMapping("/id/{id}")
    public ResponseEntity<?> deleteUserById(@PathVariable Long id) {
        log.info("Deleting user by ID: " + id);
        userService.deleteById(id);
        return ResponseEntity.ok("User deleted");
    }

    @GetMapping("/id/{id}")
    public ResponseEntity<?> getUserById(@PathVariable Long id) {
        log.info("Fetching user by ID: " + id);
        AppUser appUser = userService.getById(id);
        if (appUser == null) {
            return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
        }
        return ResponseEntity.ok(appUser);
    }

    @PutMapping("/")
    public ResponseEntity<?> updateUser(@RequestBody AppUser appUser) {
        log.info("Updating user with email: " + appUser.getEmail());
        AppUser user = userService.saveUser(appUser);
        return new ResponseEntity<>(user, HttpStatus.OK);
    }

    @PutMapping("/email/{email}")
    @PreAuthorize("authentication.principal.username == #email") // Users can update their own info
    public ResponseEntity<?> updateUserByEmail(@PathVariable String email, @RequestBody UserUpdateDTO userUpdateDTO) {
        log.info("Updating user by email: " + email);
        userService.updateUser(email, userUpdateDTO);
        return ResponseEntity.ok("User updated successfully");
    }

    @PutMapping("/id/{id}")
    @PreAuthorize("hasRole('ADMIN')") // Only Admin can update users by ID
    public ResponseEntity<?> updateUserById(@PathVariable Long id, @RequestBody UserUpdateDTO userUpdateDTO) {
        log.info("Admin updating user by ID: " + id);
        userService.updateUserById(id, userUpdateDTO);
        return ResponseEntity.ok("User updated successfully");
    }

    @PostMapping("/assign-role")
    public ResponseEntity<?> assignRoleToUser(@RequestParam String email, @RequestParam String roleName) {
        log.info("Assigning role '" + roleName + "' to user: " + email);
        AppUser appUser = userService.getUserByEmail(email);
        if (appUser == null) {
            return new ResponseEntity<>("User not found with email: " + email, HttpStatus.NOT_FOUND);
        }
        userService.assignRoleToUser(email, roleName);
        return ResponseEntity.ok("Role assigned to user");
    }

    @GetMapping("/roles/{email}")
    @PreAuthorize("hasRole('ADMIN') or authentication.principal.username == #email")
    public ResponseEntity<?> getAllRolesOfUser(@PathVariable String email) {
        log.info("Fetching all roles of user: " + email);
        AppUser appUser = userService.getUserByEmail(email);
        if (appUser == null) {
            return new ResponseEntity<>("User not found with email: " + email, HttpStatus.NOT_FOUND);
        }
        return ResponseEntity.ok(appUser.getRoles());
    }

    @PostMapping("/remove-role")
    public ResponseEntity<?> removeRoleFromUser(@RequestParam String email, @RequestParam String roleName) {
        log.info("Removing role '" + roleName + "' from user: " + email);
        AppUser appUser = userService.getUserByEmail(email);
        if (appUser == null) {
            return new ResponseEntity<>("User not found with email: " + email, HttpStatus.NOT_FOUND);
        }
        userService.removeRoleFromUser(email, roleName);
        return ResponseEntity.ok("Role removed from user");
    }
}
//@PostMapping("/login")
//public ResponseEntity<?> login(@RequestBody LogInBody body) {
//    log.trace("Logging in user with email: " + body.getEmail());
//
//    AppUser appUser = userService.getUserByEmail(body.getEmail());
//    if (appUser == null) {
//        return new ResponseEntity<>("User not found with email: " + body.getEmail(), HttpStatus.NOT_FOUND);
//    }
//
//    try {
//        Authentication authentication = authenticationManager.authenticate(
//                new UsernamePasswordAuthenticationToken(body.getEmail(), body.getPassword())
//        );
//
//        SecurityContextHolder.getContext().setAuthentication(authentication);
//
//        // ✅ Convert AppUser to Secure DTO (No password exposure)
//        AppUserDTO userDTO = userService.convertToDTO(appUser);
//
//        // ✅ Create Response Object with Message + Secure User Data
//        Map<String, Object> response = new HashMap<>();
//        response.put("message", "User logged in successfully");
//        response.put("user", userDTO);
//
//        return ResponseEntity.ok(response);
//
//    } catch (Exception e) {
//        log.error("Login failed for user: " + body.getEmail(), e);
//        return new ResponseEntity<>("Invalid credentials", HttpStatus.UNAUTHORIZED);
//    }
//}
//
//
//}
