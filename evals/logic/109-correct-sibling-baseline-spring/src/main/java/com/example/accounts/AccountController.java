package com.example.accounts;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/accounts")
public class AccountController {

    private final AccountRepository accounts;

    public AccountController(AccountRepository accounts) {
        this.accounts = accounts;
    }

    @GetMapping("/{id}")
    @PreAuthorize("#id == principal.id or hasRole('ADMIN')")
    public Account get(@PathVariable Long id) {
        return accounts.findById(id).orElseThrow();
    }

    @PutMapping("/{id}")
    @PreAuthorize("#id == principal.id")
    public Account update(@PathVariable Long id, @RequestBody AccountUpdate body) {
        Account account = accounts.findById(id).orElseThrow();
        account.setDisplayName(body.displayName());
        return accounts.save(account);
    }

    // Sibling without the authorization expression: any authenticated user can close any account.
    @DeleteMapping("/{id}")
    public void close(@PathVariable Long id) {
        accounts.deleteById(id);
    }

    @PostMapping("/{id}/export")
    @PreAuthorize("#id == principal.id")
    public Export export(@PathVariable Long id) {
        return accounts.exportAccount(id);
    }
}
