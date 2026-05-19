# Troubleshooting

### Diagnosing Environment Issues

If NexSec is not detecting tools or behaving unexpectedly, use the built-in diagnostic commands:

- **`nexsec health`**: Check the status of core components, databases, and model providers.
- **`nexsec shell doctor`**: Verify if external security binaries (nmap, nuclei, etc.) are available in your system PATH.
- **`nexsec shell platform`**: Inspect terminal, shell, and OS metadata used for command translation.

### Common Issues

- **Permission Errors**: Ensure external tools like `nmap` or `ffuf` have appropriate permissions to run (e.g., `sudo` for some nmap scans).
- **API Key Failures**:
    - Verify keys with `nexsec auth show`.
    - Set keys securely with `nexsec auth set-key <provider>`.
    - Ensure your network allows outbound traffic to the provider's API.
- **Model Planning Errors**:
    - Check `nexsec config get log_level`. If it's not `debug`, set it with `nexsec config set log_level debug` to see detailed model interactions.
    - Ensure the selected model provider is active and has credits.
- **Vault Access**:
    - If the vault is locked or inaccessible, ensure `~/.nexsec/.vault_key` exists and has restrictive permissions (600).

### Getting Help

- Run `nexsec --help` for a full list of commands.
- For detailed debugging, run commands with `NEXSEC_LOG_LEVEL=DEBUG`.
- If tests are failing locally, run `pytest -vv` and inspect the captured logs.
