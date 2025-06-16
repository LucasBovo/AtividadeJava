package controller;

import lombok.RequiredArgsConstructor;
import model.User;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import service.UserService;
import java.util.List;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping("/all")
    @PreAuthorize("hasAuthority('admin')")
    public List<User> getAllUsers() {
        return userService.findAll();
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('admin')")
    public void deleteUser(@PathVariable Long id) {
        userService.deleteById(id);
    }

    @GetMapping("/me")
    @PreAuthorize("hasAnyAuthority('user', 'admin')")
    public User getMyProfile(Authentication auth) {
        String email = auth.getName();
        return userService.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));
    }

    @PutMapping("/me")
    @PreAuthorize("hasAnyAuthority('user', 'admin')")
    public User updateMyProfile(Authentication auth, @RequestBody User updatedUser) {
        String email = auth.getName();
        User currentUser = userService.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Usuário não encontrado"));

        currentUser.setName(updatedUser.getName());
        currentUser.setPassword(updatedUser.getPassword());

        return userService.save(currentUser);
    }
}
