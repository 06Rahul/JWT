package com.example.SecurityAndJwt.Services;

    import com.example.SecurityAndJwt.Model.AppUser;
    import com.example.SecurityAndJwt.Repository.UserRepo;
    import com.example.SecurityAndJwt.Utils.UserDetailsImpl;
    import org.springframework.beans.factory.annotation.Autowired;
    import org.springframework.security.core.userdetails.UserDetails;
    import org.springframework.security.core.userdetails.UserDetailsService;
    import org.springframework.security.core.userdetails.UsernameNotFoundException;
    import org.springframework.stereotype.Service;

    @Service
    public class UserDetailServiceImpl implements UserDetailsService {

        private final UserRepo userRepo;

        @Autowired
        public UserDetailServiceImpl(UserRepo userRepo) {
            this.userRepo = userRepo;
        }

        @Override
        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
            AppUser appUser = userRepo.findByEmail(username);
            if (appUser == null) {
                throw new UsernameNotFoundException("User not found with email: " + username);
            }
            return new UserDetailsImpl(appUser);
        }}
