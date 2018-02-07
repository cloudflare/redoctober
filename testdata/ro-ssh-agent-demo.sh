export RO_USER=alice
export RO_PASS=alice

go build github.com/cloudflare/redoctober/
go build github.com/cloudflare/redoctober/cmd/ro/

# Start Papa RO using a systemd socket (On dedicated terminal)
systemd-socket-activate -l 443 \
  ./redoctober -systemdfds -vaultpath testdata/diskrecord.json \
               -certs testdata/server.crt -keys testdata/server.pem

# Add admin and users (See README.md)
# Sign on enough delegates
curl --cacert testdata/server.crt https://localhost:443/delegate \
     -d '{"Name":"alice","Password":"alice","Time":"2h34m","Uses":10}'
curl --cacert testdata/server.crt https://localhost:443/delegate \
     -d '{"Name":"bob","Password":"bob","Time":"2h34m","Uses":10}'

# Consign a private key to Papa RO
./ro -server localhost:443 -ca testdata/server.crt \
     -minUsers 2 -owners alice,bob -usages ssh-sign-with \
     -in id_ed25519 -out id_ed25519.encrypted encrypt

# Start RO SSH Agent (On dedicated terminal)
./ro -server localhost:443 -ca testdata/server.crt ssh-agent

# Set the SSH_AUTH_SOCK Environment Variable
export SSH_AUTH_SOCK=/tmp/ro_ssh_[random]/roagent.sock

# Add the encrypted key to the RO SSH Agent
./ro -in testdata/ssh_key.encrypted -pubkey testdata/ssh_key.pub ssh-add

# List public keys available through RO SSH Agent
ssh-add -L

# Profit!
