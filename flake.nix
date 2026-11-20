{
  description = "Katzenpost";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAll = f: nixpkgs.lib.genAttrs systems (s: f nixpkgs.legacyPackages.${s});
      # The version is the top entry of debian/changelog, as for the .deb.
      version = builtins.head (builtins.match "katzenpost \\(([^)]+)\\).*"
        (builtins.readFile ./debian/changelog));
    in {
      packages = forAll (pkgs: let
        # The namenlos client config; kno is its source of truth. Bump rev and
        # hash to pick up a newer one.
        clientToml = pkgs.fetchurl {
          url = "https://raw.githubusercontent.com/katzenpost/kno/674153cece50dac36c95ebaee34af9b6eba1e27f/data/networks/namenlos/.generated/configs/client.toml";
          hash = "sha256-i4pSLj7fOfzwrJ60yyH0z6rdfgryFJrIAcekbQkk0EE=";
        };
      in rec {
        default = kpclientd;
        # The same files as packaging/debian/kpclientd-deb.sh puts in the .deb.
        kpclientd = pkgs.buildGoModule {
          pname = "kpclientd";
          inherit version;
          src = ./.;
          # proxyVendor keeps the prebuilt libsqisign_ffi.a that go mod vendor drops.
          proxyVendor = true;
          vendorHash = "sha256-nGBMbHZKGFsutYYoFWx1NfQE0UjORa5dNjzjVWF4RMs=";
          buildInputs = [ pkgs.openssl ];
          subPackages = [ "cmd/kpclientd" ];
          ldflags = [ "-s" "-w" "-X github.com/katzenpost/katzenpost/common.BuildVersion=${version}" ];
          doCheck = false;
          postInstall = ''
            install -D -m0644 ${clientToml} $out/etc/katzenpost/client.toml
            install -D -m0644 debian/thinclient.toml $out/etc/katzenpost/thinclient.toml
            for u in system:katzenpost.kpclientd.service user:katzenpost.kpclientd.user.service; do
              mkdir -p $out/lib/systemd/''${u%%:*}
              substitute debian/''${u#*:} $out/lib/systemd/''${u%%:*}/kpclientd.service \
                --replace-fail /usr/bin/kpclientd $out/bin/kpclientd \
                --replace-fail /etc/katzenpost $out/etc/katzenpost
            done
          '';
          meta = {
            description = "Katzenpost thin client daemon";
            homepage = "https://katzenpost.network/";
            license = pkgs.lib.licenses.agpl3Only;
            mainProgram = "kpclientd";
            platforms = pkgs.lib.platforms.linux;
          };
        };
      });

      # kpclientd requires -c, so nix run starts it with the shipped namenlos config.
      apps = forAll (pkgs: rec {
        default = kpclientd;
        kpclientd = let p = self.packages.${pkgs.stdenv.hostPlatform.system}.kpclientd; in {
          type = "app";
          program = toString (pkgs.writeShellScript "kpclientd" ''
            exec ${p}/bin/kpclientd -c ${p}/etc/katzenpost/client.toml "$@"
          '');
        };
      });
    };
}
