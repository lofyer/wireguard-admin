# Agent Notes

## Git remotes

| Remote | URL | Notes |
|--------|-----|-------|
| origin | ssh://git@10.7.0.1:11022/root/wireguard-admin.git | Self-hosted (git.digiman.live). Port 11022 is only reachable inside the wg0 VPN tunnel, so the tunnel IP 10.7.0.1 is used instead of the public hostname. Requires wg0 to be up. |
| github | git@github.com:lofyer/wireguard-admin.git | GitHub mirror. |

Push to both after committing:

```
git push && git push github main
```
