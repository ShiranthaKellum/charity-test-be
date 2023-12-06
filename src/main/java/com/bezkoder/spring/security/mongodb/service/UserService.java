package com.bezkoder.spring.security.mongodb.service;

import com.bezkoder.spring.security.mongodb.models.ERole;
import com.bezkoder.spring.security.mongodb.models.Role;
import com.bezkoder.spring.security.mongodb.models.User;
import com.bezkoder.spring.security.mongodb.payload.request.SignupRequest;
import com.bezkoder.spring.security.mongodb.payload.request.UpdateUserRolesRequest;
import com.bezkoder.spring.security.mongodb.payload.response.RoleRequestedUser;
import com.bezkoder.spring.security.mongodb.repository.RoleRepository;
import com.bezkoder.spring.security.mongodb.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
@Slf4j
public class UserService {
    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    public User signUpUser(SignupRequest signupRequest) {
        User newUser = new User(
                signupRequest.getUsername(),
                signupRequest.getEmail(),
                encoder.encode(signupRequest.getPassword())
        );
        log.info("New user {} created", signupRequest.getUsername());
        Set<String> strRoles = signupRequest.getRoles();
        Set<Role> roles = new HashSet<>();
        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found!"));
            roles.add(userRole);
            log.info("Role `{}` is added to username {}", ERole.ROLE_USER, signupRequest.getUsername());
        } else {
            log.error("User should initially have only role `{}`", ERole.ROLE_USER);
            return null;
        }
        newUser.setRoles(roles);
        log.info("User has {} roles", roles);
        Set<String> requestedRolesSet = signupRequest.getRequestedRoles();
        if (requestedRolesSet.isEmpty()) {
            newUser.setRequestedRoles(null);
            log.info("New User has not requested any role");
        } else {
            newUser.setRequestedRoles(signupRequest.getRequestedRoles());
            log.info("User has requested {} roles", signupRequest.getRequestedRoles());
        }
        userRepository.save(newUser);
        log.info("New user is created");
        return newUser;
    }

    public User updateUserRoles(String id, UpdateUserRolesRequest updatedUserRolesRequest) {
        User existingUser = userRepository.findById(id)
                .orElse(null);
        if (existingUser != null) {
            if (updatedUserRolesRequest.getUsername() != null) {
                existingUser.setUsername(updatedUserRolesRequest.getUsername());
            }
            Set<String> roleNames = updatedUserRolesRequest.getRoles();
            Set<Role> roles = new HashSet<>();
            if (roleNames.isEmpty()) {
                return null;
            } else {
                roleNames.forEach(
                        roleName -> {
                            switch (roleName) {
                                case "admin" -> {
                                    Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                            .orElseThrow(() -> new RuntimeException("ERROR: Role " + roleName + " is not found!"));
                                    roles.add(adminRole);
                                    log.info("Role {} is added to username {}", roleName, updatedUserRolesRequest.getUsername());
                                }
                                case "doctor" -> {
                                    Role doctorRole = roleRepository.findByName(ERole.ROLE_DOCTOR)
                                            .orElseThrow(() -> new RuntimeException("ERROR: Role " + roleName + " is not found!"));
                                    roles.add(doctorRole);
                                    log.info("Role {} is added to username {}", roleName, updatedUserRolesRequest.getUsername());
                                }
                                case "contributor" -> {
                                    Role contributorRole = roleRepository.findByName(ERole.ROLE_CONTRIBUTOR)
                                            .orElseThrow(() -> new RuntimeException("ERROR: Role " + roleName + " is not found!"));
                                    roles.add(contributorRole);
                                    log.info("Role {} is added to username {}", roleName, updatedUserRolesRequest.getUsername());
                                }
                            }
                        }
                );
            }
            existingUser.setRoles(roles);
            existingUser.setRequestedRoles(null);
            userRepository.save(existingUser);
            log.info("User is updated");
        }
        return existingUser;
    }

    public List<RoleRequestedUser> getRoleRequestedUsers() {
        List<User> roleRequestedUsersWithAllDetails = userRepository.findByRequestedRolesNotNull();
        List<RoleRequestedUser> roleRequestedUsersWithTrimmedDetails = new ArrayList<>();
        roleRequestedUsersWithAllDetails.forEach(user -> {
            RoleRequestedUser roleRequestedUserWithTrimmedDetails = new RoleRequestedUser(
                    user.getId(),
                    user.getUsername(),
                    user.getRequestedRoles()
            );
            roleRequestedUsersWithTrimmedDetails.add(roleRequestedUserWithTrimmedDetails);
        });
        log.info("{} role requested users were found", roleRequestedUsersWithTrimmedDetails.size());
        return roleRequestedUsersWithTrimmedDetails;
    }
}
