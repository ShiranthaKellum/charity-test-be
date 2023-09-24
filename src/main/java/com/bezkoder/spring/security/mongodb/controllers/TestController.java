package com.bezkoder.spring.security.mongodb.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

//for Angular Client (withCredentials)
//@CrossOrigin(origins = "http://localhost:8081", maxAge = 3600, allowCredentials="true")
@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/test")
public class TestController {
  @GetMapping("/all")
  public String allAccess() {
    return "Public Content.";
  }

  @GetMapping("/user")
  @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
  public String userAccess() {
    return "User Content.";
  }

  @GetMapping("/contributor")
  @PreAuthorize("hasRole('CONTRIBUTOR')")
  public String contributorAccess() {
    return "Contributor Content.";
  }

  @GetMapping("/patient")
  @PreAuthorize("hasRole('PATIENT')")
  public String patientAccess() {
    return "Patient Content.";
  }

  @GetMapping("/doctor")
  @PreAuthorize("hasRole('DOCTOR')")
  public String doctorAccess() {
    return "Doctor Content.";
  }
}
